from __future__ import annotations

from mailguard.analyzers.common import parse_tag_pairs
from mailguard.core.dns import AsyncDNSClient
from mailguard.core.utils import flatten_tag_value
from mailguard.models import DMARCAnalysis, Finding, Severity, Status


async def analyze_dmarc(domain: str, dns_client: AsyncDNSClient) -> tuple[DMARCAnalysis, list[Finding]]:
    analysis = DMARCAnalysis()
    findings: list[Finding] = []
    records = [record for record in await dns_client.resolve_txt(f"_dmarc.{domain}") if record.lower().startswith("v=dmarc1")]
    if not records:
        analysis.issues.append("No DMARC record found.")
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="dmarc.missing",
                title="DMARC is missing",
                severity=Severity.CRITICAL,
                description="The domain does not publish a DMARC policy, which weakens spoofing protection and reporting.",
                recommendation="Publish a DMARC record starting with p=none and progress toward p=quarantine or p=reject.",
            )
        )
        return analysis, findings
    analysis.present = True
    analysis.record = records[0]
    tags = parse_tag_pairs(records[0])
    analysis.policy = tags.get("p")
    analysis.subdomain_policy = tags.get("sp")
    analysis.pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
    analysis.rua = flatten_tag_value(tags.get("rua"))
    analysis.ruf = flatten_tag_value(tags.get("ruf"))
    analysis.adkim = tags.get("adkim")
    analysis.aspf = tags.get("aspf")
    if analysis.policy == "none":
        analysis.issues.append("DMARC policy is set to none.")
        findings.append(
            Finding(
                code="dmarc.monitor_only",
                title="DMARC is monitor-only",
                severity=Severity.HIGH,
                description="DMARC is present but does not enforce action against failing mail.",
                recommendation="Advance the policy to quarantine or reject after monitoring legitimate traffic.",
                evidence=[records[0]],
            )
        )
    if analysis.pct < 100:
        analysis.issues.append("DMARC only applies to a subset of traffic (pct < 100).")
        findings.append(
            Finding(
                code="dmarc.partial",
                title="DMARC enforcement is partial",
                severity=Severity.MEDIUM,
                description="The DMARC pct tag limits enforcement to only part of the traffic.",
                recommendation="Raise pct to 100 when rollout is complete.",
                evidence=[f"pct={analysis.pct}"],
            )
        )
    if not analysis.rua:
        analysis.issues.append("No aggregate reporting URI (rua) configured.")
        findings.append(
            Finding(
                code="dmarc.no_rua",
                title="DMARC aggregate reporting missing",
                severity=Severity.LOW,
                description="The DMARC record does not specify a rua mailbox for aggregate reports.",
                recommendation="Add a rua mailbox to improve policy visibility and attack detection.",
            )
        )
    analysis.status = Status.FAIL if analysis.policy in {None, "none"} else Status.WARN if analysis.issues else Status.PASS
    return analysis, findings
