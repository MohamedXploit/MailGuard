from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from fnmatch import fnmatch
from typing import Any

from mailguard.analyzers.bimi import analyze_bimi
from mailguard.analyzers.dkim import analyze_dkim
from mailguard.analyzers.dmarc import analyze_dmarc
from mailguard.analyzers.mta_sts import analyze_mta_sts, analyze_tls_rpt
from mailguard.analyzers.mx import analyze_mx
from mailguard.analyzers.reputation import analyze_reputation
from mailguard.analyzers.smtp import analyze_smtp
from mailguard.analyzers.spf import analyze_spf
from mailguard.config import AppConfig
from mailguard.core.cache import TTLCache
from mailguard.core.dns import AsyncDNSClient
from mailguard.core.http import AsyncHTTPClient
from mailguard.models import DomainScanResult, Finding, MTASTSAnalysis, Severity, Status
from mailguard.risk_score import assess_risk

DEFAULT_CHECKS = {"mx", "spf", "dkim", "dmarc", "bimi", "mta-sts", "tls-rpt", "smtp", "reputation"}


class MailGuardScanner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.cache = TTLCache[list[str]](ttl=config.cache_ttl, max_size=config.cache_size)
        self.dns = AsyncDNSClient(config=config, cache=self.cache)
        self.http_manager = AsyncHTTPClient(config)
        self.http: AsyncHTTPClient | None = None

    async def __aenter__(self) -> "MailGuardScanner":
        self.http = await self.http_manager.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.http_manager.__aexit__(exc_type, exc, tb)

    async def scan_many(
        self,
        domains: Iterable[str],
        *,
        selected_checks: set[str] | None = None,
        dkim_selectors: list[str] | None = None,
        progress_callback: Callable[[DomainScanResult], None] | None = None,
    ) -> list[DomainScanResult]:
        ordered_domains = list(domains)
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def _runner(domain: str) -> DomainScanResult:
            async with semaphore:
                result = await self.scan_domain(
                    domain,
                    selected_checks=selected_checks,
                    dkim_selectors=dkim_selectors,
                )
                if progress_callback is not None:
                    progress_callback(result)
                return result

        tasks = [asyncio.create_task(_runner(domain)) for domain in ordered_domains]
        results_by_domain = {result.domain: result for result in await asyncio.gather(*tasks)}
        return [results_by_domain[domain] for domain in ordered_domains]

    async def scan_domain(
        self,
        domain: str,
        *,
        selected_checks: set[str] | None = None,
        dkim_selectors: list[str] | None = None,
    ) -> DomainScanResult:
        if self.http is None:
            raise RuntimeError("MailGuardScanner must be used as an async context manager.")
        checks = _expand_check_dependencies(selected_checks or DEFAULT_CHECKS)
        result = DomainScanResult(domain=domain)
        result.metadata["selected_checks"] = sorted(checks)
        result.spf.status = Status.SKIPPED
        result.dkim.status = Status.SKIPPED
        result.dmarc.status = Status.SKIPPED
        result.bimi.status = Status.SKIPPED
        result.mta_sts.status = Status.SKIPPED
        result.tls_rpt.status = Status.SKIPPED
        result.smtp.status = Status.SKIPPED
        result.reputation.status = Status.SKIPPED
        findings: list[Finding] = []
        concurrent_tasks: dict[str, asyncio.Task[Any]] = {}
        if "mx" in checks:
            concurrent_tasks["mx"] = asyncio.create_task(analyze_mx(domain, self.dns))
        if "spf" in checks:
            concurrent_tasks["spf"] = asyncio.create_task(analyze_spf(domain, self.dns))
        if "dkim" in checks:
            concurrent_tasks["dkim"] = asyncio.create_task(analyze_dkim(domain, dkim_selectors or self.config.dkim_selectors, self.dns))
        if "dmarc" in checks:
            concurrent_tasks["dmarc"] = asyncio.create_task(analyze_dmarc(domain, self.dns))
        if "mta-sts" in checks:
            concurrent_tasks["mta-sts"] = asyncio.create_task(analyze_mta_sts(domain, self.dns, self.http))
        if "tls-rpt" in checks:
            concurrent_tasks["tls-rpt"] = asyncio.create_task(analyze_tls_rpt(domain, self.dns))

        for name, task in concurrent_tasks.items():
            try:
                outcome = await task
            except Exception as exc:
                result.errors.append(f"{name}: {exc}")
                continue
            if name == "mx":
                result.mx, analyzer_findings = outcome
            elif name == "spf":
                result.spf, analyzer_findings = outcome
            elif name == "dkim":
                result.dkim, analyzer_findings = outcome
            elif name == "dmarc":
                result.dmarc, analyzer_findings = outcome
            elif name == "mta-sts":
                result.mta_sts, analyzer_findings = outcome
            else:
                result.tls_rpt, analyzer_findings = outcome
            findings.extend(analyzer_findings)

        if "bimi" in checks:
            try:
                result.bimi, analyzer_findings = await analyze_bimi(
                    domain,
                    self.config.bimi_selector,
                    result.dmarc,
                    self.dns,
                    self.http,
                )
                findings.extend(analyzer_findings)
            except Exception as exc:
                result.errors.append(f"bimi: {exc}")

        if "smtp" in checks:
            try:
                result.smtp = await analyze_smtp(result.mx, result.mta_sts, self.config)
            except Exception as exc:
                result.errors.append(f"smtp: {exc}")

        if "reputation" in checks:
            try:
                result.reputation, analyzer_findings = await analyze_reputation(result.mx, self.http, self.config)
                findings.extend(analyzer_findings)
            except Exception as exc:
                result.errors.append(f"reputation: {exc}")

        findings.extend(_validate_mta_sts_mx_alignment(result.mta_sts, result.mx))
        result.findings = findings
        result.risk = assess_risk(result)
        result.dns_cache = self.cache.stats()
        return result


def _expand_check_dependencies(checks: set[str]) -> set[str]:
    normalized = {item.lower() for item in checks}
    if "bimi" in normalized:
        normalized.add("dmarc")
    if "smtp" in normalized:
        normalized.update({"mx", "mta-sts"})
    if "reputation" in normalized:
        normalized.add("mx")
    return normalized


def _validate_mta_sts_mx_alignment(mta_sts: MTASTSAnalysis, mx_hosts: list) -> list[Finding]:
    if not mta_sts.policy or not mta_sts.policy.mx_patterns:
        return []
    unmatched = [host.hostname for host in mx_hosts if not any(fnmatch(host.hostname, pattern) for pattern in mta_sts.policy.mx_patterns)]
    if not unmatched:
        return []
    return [
        Finding(
            code="mta_sts.mx_mismatch",
            title="MTA-STS policy does not cover all MX hosts",
            severity=Severity.HIGH,
            description="At least one MX hostname does not match the published MTA-STS mx patterns.",
            recommendation="Update the MTA-STS mx rules or adjust MX records so they match the enforced policy.",
            evidence=unmatched,
        )
    ]
