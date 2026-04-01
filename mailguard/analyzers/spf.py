from __future__ import annotations

import re

from mailguard.core.dns import AsyncDNSClient
from mailguard.models import Finding, SPFAnalysis, Severity, Status

SPF_LOOKUP_RE = re.compile(r"^(include:|redirect=|exists:|a(?::|$)|mx(?::|$)|ptr(?::|$))", re.IGNORECASE)


async def analyze_spf(domain: str, dns_client: AsyncDNSClient) -> tuple[SPFAnalysis, list[Finding]]:
    analysis = SPFAnalysis()
    findings: list[Finding] = []
    records = [record for record in await dns_client.resolve_txt(domain) if record.lower().startswith("v=spf1")]
    if not records:
        analysis.issues.append("No SPF record found.")
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="spf.missing",
                title="SPF is missing",
                severity=Severity.HIGH,
                description="The domain does not publish an SPF policy.",
                recommendation="Publish an SPF record with explicit sending sources and a hard fail policy when ready.",
            )
        )
        return analysis, findings
    if len(records) > 1:
        analysis.issues.append("Multiple SPF records detected.")
        analysis.status = Status.FAIL
        findings.append(
            Finding(
                code="spf.multiple",
                title="Multiple SPF records",
                severity=Severity.HIGH,
                description="More than one SPF record is published, which causes permanent SPF evaluation failure.",
                recommendation="Consolidate to a single SPF record.",
                evidence=records,
            )
        )
    analysis.present = True
    analysis.record = records[0]
    visited: set[str] = set()
    await _walk_spf(domain, analysis.record, dns_client, analysis, visited)
    if analysis.all_qualifier == "+":
        analysis.issues.append("SPF ends with +all and effectively authorizes every sender.")
        findings.append(
            Finding(
                code="spf.permissive",
                title="SPF allows all senders",
                severity=Severity.CRITICAL,
                description="The SPF policy terminates with +all, making spoofing trivial.",
                recommendation="Replace +all with -all after validating legitimate senders, or use ~all temporarily during rollout.",
                evidence=[analysis.record],
            )
        )
    elif analysis.all_qualifier == "~":
        analysis.issues.append("SPF uses softfail (~all), which reduces enforcement strength.")
        findings.append(
            Finding(
                code="spf.softfail",
                title="SPF only soft-fails",
                severity=Severity.MEDIUM,
                description="The SPF policy uses ~all, which still allows suspicious mail to pass downstream handling more often than -all.",
                recommendation="Tighten the SPF policy to -all after validating all legitimate sources.",
                evidence=[analysis.record],
            )
        )
    if analysis.lookup_count > 10:
        analysis.issues.append("SPF exceeds the RFC lookup limit of 10 DNS mechanisms.")
        findings.append(
            Finding(
                code="spf.lookup_limit",
                title="SPF exceeds DNS lookup budget",
                severity=Severity.HIGH,
                description="The SPF policy appears to require more than 10 DNS lookups and may fail for receivers.",
                recommendation="Flatten or simplify SPF includes and redirect chains.",
                evidence=[f"lookups={analysis.lookup_count}"],
            )
        )
    if any("PTR" in issue for issue in analysis.issues):
        findings.append(
            Finding(
                code="spf.ptr",
                title="SPF uses PTR mechanism",
                severity=Severity.MEDIUM,
                description="PTR-based SPF authorization is discouraged and often unreliable.",
                recommendation="Replace PTR with explicit include, ip4, ip6, a, or mx mechanisms.",
            )
        )
    if any("no SPF record" in issue for issue in analysis.issues):
        findings.append(
            Finding(
                code="spf.dangling_include",
                title="SPF include target is stale",
                severity=Severity.HIGH,
                description="At least one SPF include or redirect target does not publish its own SPF record.",
                recommendation="Remove or replace dead include targets and re-validate the SPF chain.",
                evidence=[issue for issue in analysis.issues if "no SPF record" in issue],
            )
        )
    analysis.status = Status.FAIL if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings) else Status.WARN if analysis.issues else Status.PASS
    return analysis, findings


async def _walk_spf(
    domain: str,
    record: str,
    dns_client: AsyncDNSClient,
    analysis: SPFAnalysis,
    visited: set[str],
) -> None:
    if domain in visited:
        return
    visited.add(domain)
    analysis.recursion_chain.append(domain)
    tokens = record.split()
    for token in tokens[1:]:
        normalized = token.lower()
        mechanism = normalized[1:] if normalized[:1] in {"+", "-", "~", "?"} else normalized
        if mechanism.endswith("all"):
            analysis.all_qualifier = normalized[:1] if normalized[:1] in {"+", "-", "~", "?"} else "+"
        if SPF_LOOKUP_RE.match(mechanism):
            analysis.lookup_count += 1
        if mechanism.startswith("include:"):
            included_domain = mechanism.split(":", 1)[1]
            analysis.includes.append(included_domain)
            await _resolve_nested_spf(included_domain, dns_client, analysis, visited)
        elif mechanism.startswith("redirect="):
            redirected_domain = mechanism.split("=", 1)[1]
            analysis.redirects.append(redirected_domain)
            await _resolve_nested_spf(redirected_domain, dns_client, analysis, visited)
        elif mechanism.startswith("ptr"):
            analysis.issues.append("PTR mechanism present in SPF policy.")


async def _resolve_nested_spf(
    domain: str,
    dns_client: AsyncDNSClient,
    analysis: SPFAnalysis,
    visited: set[str],
) -> None:
    records = [record for record in await dns_client.resolve_txt(domain) if record.lower().startswith("v=spf1")]
    if not records:
        analysis.issues.append(f"Include target {domain} has no SPF record.")
        return
    await _walk_spf(domain, records[0], dns_client, analysis, visited)
