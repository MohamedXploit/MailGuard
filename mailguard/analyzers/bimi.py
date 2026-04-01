from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from mailguard.analyzers.common import parse_tag_pairs
from mailguard.core.dns import AsyncDNSClient
from mailguard.core.http import AsyncHTTPClient
from mailguard.models import BIMIAnalysis, DMARCAnalysis, Finding, Severity, Status, VMCCertificate


async def analyze_bimi(
    domain: str,
    selector: str,
    dmarc: DMARCAnalysis,
    dns_client: AsyncDNSClient,
    http_client: AsyncHTTPClient,
) -> tuple[BIMIAnalysis, list[Finding]]:
    record_name = f"{selector}._bimi.{domain}"
    analysis = BIMIAnalysis(selector=selector, record_name=record_name)
    findings: list[Finding] = []
    records = [record for record in await dns_client.resolve_txt(record_name) if record.lower().startswith("v=bimi1")]
    if not records:
        analysis.issues.append("No BIMI record found.")
        analysis.status = Status.INFO
        return analysis, findings
    analysis.present = True
    analysis.record = records[0]
    tags = parse_tag_pairs(records[0])
    analysis.logo_url = tags.get("l")
    analysis.authority_url = tags.get("a")
    if dmarc.policy not in {"quarantine", "reject"} or dmarc.pct < 100:
        analysis.issues.append("BIMI requires an enforcing DMARC policy with pct=100.")
        findings.append(
            Finding(
                code="bimi.dmarc_prereq",
                title="BIMI published without DMARC enforcement",
                severity=Severity.MEDIUM,
                description="The domain publishes BIMI but does not meet the DMARC enforcement prerequisites.",
                recommendation="Move DMARC to p=quarantine or p=reject with pct=100 before relying on BIMI.",
            )
        )
    if analysis.logo_url:
        if not analysis.logo_url.lower().startswith("https://"):
            analysis.issues.append("BIMI logo must be hosted over HTTPS.")
        if ".svg" not in analysis.logo_url.lower():
            analysis.issues.append("BIMI logo should point to an SVG asset.")
        analysis.logo_accessible = await _url_is_accessible(analysis.logo_url, http_client)
        if not analysis.logo_accessible:
            analysis.issues.append("BIMI logo URL is not reachable or does not return success.")
            findings.append(
                Finding(
                    code="bimi.logo_unreachable",
                    title="BIMI logo cannot be fetched",
                    severity=Severity.MEDIUM,
                    description="The BIMI l= URL is not reachable over HTTPS.",
                    recommendation="Host the SVG Tiny PS logo on an accessible HTTPS endpoint.",
                    evidence=[analysis.logo_url],
                )
            )
    if analysis.authority_url:
        if not analysis.authority_url.lower().startswith("https://"):
            analysis.issues.append("BIMI authority certificate should be hosted over HTTPS.")
        analysis.vmc = await _fetch_vmc(analysis.authority_url, http_client)
        if not analysis.vmc.valid_format or analysis.vmc.errors:
            findings.append(
                Finding(
                    code="bimi.vmc_invalid",
                    title="VMC validation failed",
                    severity=Severity.MEDIUM,
                    description="MailGuard could not validate the authority certificate referenced by the BIMI record.",
                    recommendation="Publish a valid accessible VMC and confirm it is not expired.",
                    evidence=[analysis.authority_url, *analysis.vmc.errors],
                )
            )
    else:
        analysis.issues.append("No authority (a=) URL present for BIMI.")
    analysis.status = Status.FAIL if any(item.severity in {Severity.HIGH, Severity.CRITICAL} for item in findings) else Status.WARN if analysis.issues else Status.PASS
    return analysis, findings


async def _url_is_accessible(url: str, http_client: AsyncHTTPClient) -> bool:
    try:
        response = await http_client.head(url)
        if response.status_code < 400:
            return True
        response = await http_client.get(url)
        return response.status_code < 400
    except Exception:
        return False


async def _fetch_vmc(url: str, http_client: AsyncHTTPClient) -> VMCCertificate:
    vmc = VMCCertificate(url=url)
    try:
        response = await http_client.get(url)
    except Exception as exc:
        vmc.errors.append(str(exc))
        return vmc
    if response.status_code >= 400:
        vmc.errors.append(f"HTTP {response.status_code}")
        return vmc
    vmc.fetched = True
    raw = response.content
    certificates: list[x509.Certificate] = []
    loaders = [
        lambda data: [x509.load_pem_x509_certificate(data)],
        lambda data: [x509.load_der_x509_certificate(data)],
        pkcs7.load_pem_pkcs7_certificates,
        pkcs7.load_der_pkcs7_certificates,
    ]
    for loader in loaders:
        try:
            certificates = list(loader(raw))
            if certificates:
                break
        except Exception:
            continue
    if not certificates:
        vmc.errors.append("Unable to parse VMC as X.509 or PKCS7 data.")
        return vmc
    certificate = certificates[0]
    vmc.parsed = True
    vmc.valid_format = True
    vmc.issuer = certificate.issuer.rfc4514_string()
    vmc.subject = certificate.subject.rfc4514_string()
    vmc.serial_number = hex(certificate.serial_number)
    vmc.expires_at = certificate.not_valid_after_utc if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after.replace(tzinfo=UTC)
    if vmc.expires_at <= datetime.now(UTC):
        vmc.errors.append("Certificate is expired.")
    return vmc
