from __future__ import annotations

import asyncio
from typing import Iterable

from mailguard.core.dns import AsyncDNSClient
from mailguard.models import Finding, MXHost, Severity, Status

TAKEOVER_PROVIDERS: dict[str, str] = {
    ".herokudns.com": "Heroku",
    ".azurewebsites.net": "Azure App Service",
    ".cloudapp.net": "Microsoft Azure",
    ".github.io": "GitHub Pages",
    ".pages.dev": "Cloudflare Pages",
    ".fastly.net": "Fastly",
    ".surge.sh": "Surge",
    ".pantheonsite.io": "Pantheon",
    ".unbouncepages.com": "Unbounce",
    ".readme.io": "ReadMe",
}


async def analyze_mx(domain: str, dns_client: AsyncDNSClient) -> tuple[list[MXHost], list[Finding]]:
    findings: list[Finding] = []
    records = await dns_client.resolve_mx(domain)
    if not records:
        findings.append(
            Finding(
                code="mx.missing",
                title="No MX record published",
                severity=Severity.HIGH,
                description="The domain does not publish MX records, which can break or unexpectedly reroute inbound mail.",
                recommendation="Publish explicit MX records or document that the domain intentionally does not receive email.",
            )
        )
        return [], findings
    analyzed = await asyncio.gather(
        *[_analyze_mx_host(domain, priority, host, dns_client) for priority, host in records]
    )
    mx_hosts = list(analyzed)
    dangling = [item.hostname for item in mx_hosts if item.dangling]
    if dangling:
        findings.append(
            Finding(
                code="mx.dangling",
                title="Dangling MX host detected",
                severity=Severity.CRITICAL,
                description="One or more MX hosts do not resolve to usable addresses.",
                recommendation="Remove stale MX records or restore the referenced mail hosts before attackers can claim them.",
                evidence=dangling,
            )
        )
    takeover = [item.hostname for item in mx_hosts if item.takeover_suspected]
    if takeover:
        findings.append(
            Finding(
                code="mx.takeover",
                title="Potential MX subdomain takeover path",
                severity=Severity.HIGH,
                description="An MX endpoint points at an unclaimed third-party hostname pattern often abused in subdomain takeover scenarios.",
                recommendation="Replace the orphaned hostname with an actively managed mail endpoint and confirm ownership with the provider.",
                evidence=takeover,
            )
        )
    return mx_hosts, findings


async def _analyze_mx_host(domain: str, priority: int, host: str, dns_client: AsyncDNSClient) -> MXHost:
    addresses_task = asyncio.create_task(_resolve_addresses(dns_client, host))
    cname_task = asyncio.create_task(dns_client.resolve_cname(host))
    addresses, aliases = await asyncio.gather(addresses_task, cname_task)
    issues: list[str] = []
    dangling = False
    takeover_suspected = False
    takeover_provider: str | None = None
    if not addresses:
        dangling = True
        issues.append("MX target does not resolve to A or AAAA records.")
    if host.endswith(f".{domain}") and not addresses:
        issues.append("In-domain MX target appears stale and could be reclaimable.")
    alias_provider = _match_takeover_provider(aliases)
    if alias_provider and not addresses:
        takeover_suspected = True
        takeover_provider = alias_provider
        issues.append(f"CNAME target matches common takeover provider footprint: {alias_provider}.")
    status = Status.FAIL if dangling or takeover_suspected else Status.PASS
    return MXHost(
        hostname=host,
        priority=priority,
        addresses=addresses,
        aliases=aliases,
        dangling=dangling,
        takeover_suspected=takeover_suspected,
        takeover_provider=takeover_provider,
        issues=issues,
        status=status,
    )


async def _resolve_addresses(dns_client: AsyncDNSClient, host: str) -> list[str]:
    a_records, aaaa_records = await asyncio.gather(dns_client.resolve_a(host), dns_client.resolve_aaaa(host))
    return [*a_records, *aaaa_records]


def _match_takeover_provider(aliases: Iterable[str]) -> str | None:
    for alias in aliases:
        lowered = alias.lower()
        for suffix, provider in TAKEOVER_PROVIDERS.items():
            if lowered.endswith(suffix):
                return provider
    return None
