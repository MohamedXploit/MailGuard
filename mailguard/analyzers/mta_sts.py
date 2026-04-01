from __future__ import annotations

from mailguard.analyzers.common import parse_tag_pairs
from mailguard.core.dns import AsyncDNSClient
from mailguard.core.http import AsyncHTTPClient
from mailguard.core.utils import flatten_tag_value
from mailguard.models import Finding, MTASTSAnalysis, MTASTSPolicy, Severity, Status, TLSRPTAnalysis


async def analyze_mta_sts(
    domain: str,
    dns_client: AsyncDNSClient,
    http_client: AsyncHTTPClient,
) -> tuple[MTASTSAnalysis, list[Finding]]:
    analysis = MTASTSAnalysis(policy_url=f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    findings: list[Finding] = []
    records = [record for record in await dns_client.resolve_txt(f"_mta-sts.{domain}") if record.lower().startswith("v=stsv1")]
    if not records:
        analysis.issues.append("No MTA-STS DNS record found.")
        analysis.status = Status.WARN
        findings.append(
            Finding(
                code="mta_sts.missing",
                title="MTA-STS is missing",
                severity=Severity.MEDIUM,
                description="The domain does not publish MTA-STS, so inbound SMTP is more exposed to TLS downgrade or MX interception attacks.",
                recommendation="Publish _mta-sts TXT and a matching HTTPS policy file.",
            )
        )
        return analysis, findings
    analysis.present = True
    analysis.dns_record = records[0]
    tags = parse_tag_pairs(records[0])
    analysis.policy_id = tags.get("id")
    try:
        response = await http_client.get(analysis.policy_url)
        analysis.fetch_status = response.status_code
    except Exception as exc:
        analysis.issues.append(str(exc))
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="mta_sts.fetch_failed",
                title="MTA-STS policy could not be fetched",
                severity=Severity.HIGH,
                description="The MTA-STS DNS record exists but the HTTPS policy endpoint could not be retrieved.",
                recommendation="Serve a valid HTTPS policy from /.well-known/mta-sts.txt on mta-sts.<domain>.",
                evidence=[str(exc)],
            )
        )
        return analysis, findings
    if response.status_code >= 400:
        analysis.issues.append(f"Policy endpoint returned HTTP {response.status_code}.")
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="mta_sts.http_error",
                title="MTA-STS policy endpoint is unhealthy",
                severity=Severity.HIGH,
                description="The MTA-STS policy endpoint did not return a success status code.",
                recommendation="Restore the HTTPS policy endpoint and confirm the TXT policy id matches the served file.",
                evidence=[f"HTTP {response.status_code}"],
            )
        )
        return analysis, findings
    analysis.policy = parse_mta_sts_policy(response.text)
    if not analysis.policy.valid:
        analysis.issues.extend(analysis.policy.issues)
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="mta_sts.invalid_policy",
                title="MTA-STS policy is invalid",
                severity=Severity.HIGH,
                description="The MTA-STS policy file is reachable but malformed or incomplete.",
                recommendation="Ensure the policy contains version, mode, max_age, and MX patterns when required.",
                evidence=analysis.policy.issues,
            )
        )
        return analysis, findings
    if analysis.policy.mode in {"testing", "none"}:
        findings.append(
            Finding(
                code="mta_sts.not_enforcing",
                title="MTA-STS is not enforcing",
                severity=Severity.MEDIUM,
                description="The MTA-STS policy is present but not in enforce mode.",
                recommendation="Move MTA-STS to mode=enforce once TLS and MX coverage are verified.",
                evidence=[f"mode={analysis.policy.mode}"],
            )
        )
    analysis.status = Status.PASS if analysis.policy.mode == "enforce" else Status.WARN
    return analysis, findings


def parse_mta_sts_policy(raw_policy: str) -> MTASTSPolicy:
    tags: dict[str, list[str]] = {"mx": []}
    for line in raw_policy.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if key.strip().lower() == "mx":
            tags.setdefault("mx", []).append(value.strip())
        else:
            tags[key.strip().lower()] = [value.strip()]
    policy = MTASTSPolicy(raw_policy=raw_policy)
    policy.version = _first(tags.get("version"))
    policy.mode = _first(tags.get("mode"))
    max_age = _first(tags.get("max_age"))
    policy.mx_patterns = tags.get("mx", [])
    if max_age and max_age.isdigit():
        policy.max_age = int(max_age)
    else:
        policy.issues.append("Missing or invalid max_age value.")
    if policy.version != "STSv1":
        policy.issues.append("Policy version must be STSv1.")
    if policy.mode not in {"enforce", "testing", "none"}:
        policy.issues.append("Policy mode must be enforce, testing, or none.")
    if policy.mode in {"enforce", "testing"} and not policy.mx_patterns:
        policy.issues.append("Policy mode requires one or more MX patterns.")
    policy.valid = not policy.issues
    return policy


async def analyze_tls_rpt(domain: str, dns_client: AsyncDNSClient) -> tuple[TLSRPTAnalysis, list[Finding]]:
    analysis = TLSRPTAnalysis()
    findings: list[Finding] = []
    records = [record for record in await dns_client.resolve_txt(f"_smtp._tls.{domain}") if record.lower().startswith("v=tlsrptv1")]
    if not records:
        analysis.issues.append("No TLS-RPT record found.")
        analysis.status = Status.WARN
        findings.append(
            Finding(
                code="tls_rpt.missing",
                title="TLS-RPT is missing",
                severity=Severity.LOW,
                description="No TLS reporting mailbox is configured for inbound SMTP telemetry.",
                recommendation="Publish a TLS-RPT record with an aggregate reporting mailbox.",
            )
        )
        return analysis, findings
    analysis.present = True
    analysis.record = records[0]
    tags = parse_tag_pairs(records[0])
    analysis.rua = flatten_tag_value(tags.get("rua"))
    if not analysis.rua:
        analysis.issues.append("TLS-RPT record does not specify rua targets.")
        analysis.status = Status.WARN
    else:
        analysis.status = Status.PASS
    return analysis, findings


def _first(values: list[str] | None) -> str | None:
    return values[0] if values else None
