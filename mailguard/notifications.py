from __future__ import annotations

from mailguard.config import AppConfig
from mailguard.core.http import AsyncHTTPClient
from mailguard.models import DomainScanResult, Severity


async def send_alerts(results: list[DomainScanResult], config: AppConfig, http_client: AsyncHTTPClient) -> None:
    message = build_alert_message(results)
    if not message:
        return
    if config.slack_webhook_url:
        await http_client.post(str(config.slack_webhook_url), json={"text": message})
    if config.telegram_bot_token and config.telegram_chat_id:
        await http_client.post(
            f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage",
            data={"chat_id": config.telegram_chat_id, "text": message},
        )


def build_alert_message(results: list[DomainScanResult]) -> str:
    lines: list[str] = []
    for result in results:
        critical = [finding for finding in result.findings if finding.severity in {Severity.CRITICAL, Severity.HIGH}]
        if not critical and result.risk.score >= 80:
            continue
        lines.append(f"{result.domain}: risk {result.risk.score}/100 ({result.risk.grade})")
        if critical:
            lines.extend(f"- {finding.severity.value.upper()}: {finding.title}" for finding in critical[:4])
    return "\n".join(lines)
