from __future__ import annotations

import asyncio

from mailguard.analyzers.common import estimate_b64_key_bits, parse_tag_pairs
from mailguard.core.dns import AsyncDNSClient
from mailguard.models import DKIMAnalysis, DKIMKey, Finding, Severity, Status


async def analyze_dkim(
    domain: str,
    selectors: list[str],
    dns_client: AsyncDNSClient,
) -> tuple[DKIMAnalysis, list[Finding]]:
    analysis = DKIMAnalysis(selectors_tested=selectors)
    findings: list[Finding] = []
    keys = await asyncio.gather(*[_resolve_selector(domain, selector, dns_client) for selector in selectors])
    analysis.keys = [item for item in keys if item is not None]
    if not analysis.keys:
        analysis.status = Status.WARN
        analysis.issues.append("No DKIM records were found for the tested selectors.")
        findings.append(
            Finding(
                code="dkim.not_found",
                title="DKIM selectors not found",
                severity=Severity.MEDIUM,
                description="MailGuard did not find DKIM keys for the supplied common selectors. DKIM may still exist under non-standard selector names.",
                recommendation="Validate active selector names from your mail platform and publish 2048-bit keys.",
            )
        )
        return analysis, findings
    weak_selectors = [item.record_name for item in analysis.keys if item.key_length and item.key_length < 2048]
    revoked_selectors = [item.record_name for item in analysis.keys if item.present and item.key_length in {None, 0}]
    if weak_selectors:
        findings.append(
            Finding(
                code="dkim.weak_key",
                title="Weak DKIM key length",
                severity=Severity.HIGH,
                description="At least one DKIM selector publishes a key shorter than 2048 bits.",
                recommendation="Rotate DKIM selectors to 2048-bit RSA or stronger keys.",
                evidence=weak_selectors,
            )
        )
    if revoked_selectors:
        findings.append(
            Finding(
                code="dkim.revoked",
                title="Empty DKIM public key",
                severity=Severity.MEDIUM,
                description="A DKIM selector publishes an empty p= value, which normally indicates revocation or broken configuration.",
                recommendation="Remove unused selectors or publish the intended public key.",
                evidence=revoked_selectors,
            )
        )
    analysis.status = Status.FAIL if weak_selectors else Status.PASS
    return analysis, findings


async def _resolve_selector(domain: str, selector: str, dns_client: AsyncDNSClient) -> DKIMKey | None:
    record_name = f"{selector}._domainkey.{domain}"
    txt_records = await dns_client.resolve_txt(record_name)
    dkim_record = next((record for record in txt_records if "v=DKIM1" in record.upper() or "p=" in record), None)
    if not dkim_record:
        return None
    tags = parse_tag_pairs(dkim_record)
    public_key = tags.get("p", "")
    key_length = estimate_b64_key_bits(public_key) if public_key else 0
    notes: list[str] = []
    if key_length is not None and key_length < 1024:
        notes.append("Cryptographically weak key length.")
    hash_algorithms = tags.get("h", "").split(":") if tags.get("h") else []
    return DKIMKey(
        selector=selector,
        record_name=record_name,
        present=True,
        key_type=tags.get("k", "rsa"),
        key_length=key_length,
        hash_algorithms=[item for item in hash_algorithms if item],
        notes=notes,
        status=Status.FAIL if key_length and key_length < 2048 else Status.PASS,
    )
