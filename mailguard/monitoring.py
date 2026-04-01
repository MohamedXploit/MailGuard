from __future__ import annotations

import asyncio

from mailguard.config import AppConfig
from mailguard.core.http import AsyncHTTPClient
from mailguard.notifications import send_alerts
from mailguard.scanner import MailGuardScanner


async def monitor_domains(
    domains: list[str],
    config: AppConfig,
    *,
    interval_seconds: int,
    cycles: int | None = None,
    selected_checks: set[str] | None = None,
) -> None:
    completed_cycles = 0
    while cycles is None or completed_cycles < cycles:
        async with MailGuardScanner(config) as scanner:
            results = await scanner.scan_many(
                domains,
                selected_checks=selected_checks,
            )
        actionable = [
            result
            for result in results
            if result.risk.score < 80 or any(finding.severity.value in {"critical", "high"} for finding in result.findings)
        ]
        if actionable and (config.slack_webhook_url or (config.telegram_bot_token and config.telegram_chat_id)):
            async with AsyncHTTPClient(config) as http_client:
                await send_alerts(actionable, config, http_client)
        completed_cycles += 1
        if cycles is not None and completed_cycles >= cycles:
            break
        await asyncio.sleep(interval_seconds)
