from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from urllib.parse import urlencode

from mailguard.config import AppConfig
from mailguard.core.http import AsyncHTTPClient
from mailguard.core.utils import is_public_ip
from mailguard.models import Finding, IPReputation, MXHost, ReputationAnalysis, Severity, Status


async def analyze_reputation(
    mx_hosts: list[MXHost],
    http_client: AsyncHTTPClient,
    config: AppConfig,
) -> tuple[ReputationAnalysis, list[Finding]]:
    analysis = ReputationAnalysis()
    findings: list[Finding] = []
    public_pairs = [(host.hostname, ip) for host in mx_hosts for ip in host.addresses if is_public_ip(ip)]
    if not public_pairs:
        analysis.status = Status.SKIPPED
        analysis.issues.append("No public MX addresses available for reputation lookups.")
        return analysis, findings
    if not config.virustotal_api_key and not config.abuseipdb_api_key:
        analysis.status = Status.SKIPPED
        analysis.issues.append("VirusTotal and AbuseIPDB API keys are not configured.")
        return analysis, findings
    results = await asyncio.gather(
        *[_lookup_ip(hostname, ip, http_client, config) for hostname, ip in public_pairs]
    )
    for hostname, items in results:
        if not items:
            continue
        analysis.hosts.setdefault(hostname, []).extend(items)
    analysis.status = Status.PASS
    for hostname, items in analysis.hosts.items():
        risky = [
            item
            for item in items
            if (item.malicious and item.malicious > 0)
            or (item.abuse_confidence_score and item.abuse_confidence_score >= 50)
        ]
        if risky:
            analysis.status = Status.WARN
            findings.append(
                Finding(
                    code="reputation.risky_mx",
                    title="MX host reputation issue",
                    severity=Severity.HIGH,
                    description="One or more MX server IPs have poor reputation in external intelligence sources.",
                    recommendation="Review the affected mail hosts for compromise, spam history, or misconfiguration and remediate before they are blocklisted.",
                    evidence=[f"{hostname}: {item.ip}" for item in risky],
                )
            )
    return analysis, findings


async def _lookup_ip(
    hostname: str,
    ip: str,
    http_client: AsyncHTTPClient,
    config: AppConfig,
) -> tuple[str, list[IPReputation]]:
    tasks = []
    if config.virustotal_api_key:
        tasks.append(_virustotal_lookup(ip, http_client, config.virustotal_api_key))
    if config.abuseipdb_api_key:
        tasks.append(_abuseipdb_lookup(ip, http_client, config.abuseipdb_api_key))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    reputation_items = [result for result in results if isinstance(result, IPReputation)]
    return hostname, reputation_items


async def _virustotal_lookup(ip: str, http_client: AsyncHTTPClient, api_key: str) -> IPReputation | None:
    response = await http_client.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
        is_api=True,
    )
    if response.status_code >= 400:
        return None
    payload = response.json().get("data", {}).get("attributes", {})
    stats = payload.get("last_analysis_stats", {})
    last_analysis = payload.get("last_analysis_date")
    return IPReputation(
        ip=ip,
        provider="VirusTotal",
        malicious=stats.get("malicious"),
        suspicious=stats.get("suspicious"),
        country=payload.get("country"),
        last_analysis_date=datetime.fromtimestamp(last_analysis, UTC) if last_analysis else None,
        details={"reputation": payload.get("reputation")},
        status=Status.WARN if stats.get("malicious", 0) > 0 else Status.PASS,
    )


async def _abuseipdb_lookup(ip: str, http_client: AsyncHTTPClient, api_key: str) -> IPReputation | None:
    query = urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
    response = await http_client.get(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": api_key, "Accept": "application/json"},
        is_api=True,
    )
    if response.status_code >= 400:
        return None
    payload = response.json().get("data", {})
    return IPReputation(
        ip=ip,
        provider="AbuseIPDB",
        abuse_confidence_score=payload.get("abuseConfidenceScore"),
        country=payload.get("countryCode"),
        details={
            "usage_type": payload.get("usageType"),
            "domain": payload.get("domain"),
            "total_reports": payload.get("totalReports"),
        },
        status=Status.WARN if payload.get("abuseConfidenceScore", 0) >= 50 else Status.PASS,
    )
