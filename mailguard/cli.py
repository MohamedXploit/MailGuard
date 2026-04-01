from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from mailguard import __version__
from mailguard.config import AppConfig
from mailguard.core.utils import parse_domain_sources
from mailguard.logging_utils import configure_logging
from mailguard.models import DomainScanResult, ETHICAL_WARNING, Severity
from mailguard.monitoring import monitor_domains
from mailguard.reports.generator import ReportGenerator
from mailguard.scanner import DEFAULT_CHECKS, MailGuardScanner

app = typer.Typer(help="MailGuard email security scanner", no_args_is_help=True, rich_markup_mode="markdown")
console = Console()


@app.command()
def scan(
    domains: Annotated[list[str], typer.Argument(help="Domain(s), comma-separated values, or a file path.")],
    config_path: Annotated[Path | None, typer.Option("--config", help="Optional TOML config file.")] = None,
    check: Annotated[list[str] | None, typer.Option("--check", help="Specific checks to run. Repeatable.")] = None,
    selectors: Annotated[str | None, typer.Option("--dkim-selectors", help="Comma-separated DKIM selectors to test.")] = None,
    concurrency: Annotated[int | None, typer.Option("--concurrency", help="Concurrent domain scan limit.")] = None,
    json_out: Annotated[Path | None, typer.Option("--json-out", help="Write JSON results.")] = None,
    csv_out: Annotated[Path | None, typer.Option("--csv-out", help="Write CSV results.")] = None,
    html_out: Annotated[Path | None, typer.Option("--html-out", help="Write HTML report.")] = None,
    progress: Annotated[bool, typer.Option("--progress/--no-progress", help="Display a progress bar.")] = True,
    json_logs: Annotated[bool, typer.Option("--json-logs", help="Emit JSON logs.")] = False,
    use_tor: Annotated[bool | None, typer.Option("--tor/--no-tor", help="Route HTTP requests through Tor when configured.")] = None,
) -> None:
    targets = parse_domain_sources(domains)
    if not targets:
        raise typer.BadParameter("No valid domains were supplied.")
    config = AppConfig.load(
        config_path,
        concurrency=concurrency,
        json_logs=json_logs,
        use_tor=use_tor,
    )
    configure_logging(config.log_level, config.json_logs)
    selected_checks = {item.lower() for item in (check or DEFAULT_CHECKS)}
    dkim_selectors = [item.strip() for item in selectors.split(",") if item.strip()] if selectors else config.dkim_selectors
    console.print(f"[bold yellow]Ethical warning:[/bold yellow] {ETHICAL_WARNING}")
    results = asyncio.run(
        _scan_async(
            targets,
            config,
            selected_checks=selected_checks,
            dkim_selectors=dkim_selectors,
            show_progress=progress,
        )
    )
    generator = ReportGenerator(config)
    report_errors: list[str] = []
    report_errors.extend(_write_reports(generator, results, json_out=json_out, csv_out=csv_out, html_out=html_out))
    _print_summary(results)
    exit_code = _exit_code(results)
    if report_errors:
        exit_code = 1
    raise typer.Exit(code=exit_code)


@app.command()
def monitor(
    domains: Annotated[list[str], typer.Argument(help="Domain(s), comma-separated values, or a file path.")],
    interval_seconds: Annotated[int, typer.Option("--interval", min=60, help="Polling interval in seconds.")] = 3600,
    cycles: Annotated[int | None, typer.Option("--cycles", help="Number of cycles to run before exiting.")] = None,
    config_path: Annotated[Path | None, typer.Option("--config", help="Optional TOML config file.")] = None,
    check: Annotated[list[str] | None, typer.Option("--check", help="Specific checks to run. Repeatable.")] = None,
    json_logs: Annotated[bool, typer.Option("--json-logs", help="Emit JSON logs.")] = False,
) -> None:
    targets = parse_domain_sources(domains)
    if not targets:
        raise typer.BadParameter("No valid domains were supplied.")
    config = AppConfig.load(config_path, json_logs=json_logs)
    configure_logging(config.log_level, config.json_logs)
    console.print(f"[bold yellow]Ethical warning:[/bold yellow] {ETHICAL_WARNING}")
    asyncio.run(
        monitor_domains(
            targets,
            config,
            interval_seconds=interval_seconds,
            cycles=cycles,
            selected_checks={item.lower() for item in (check or DEFAULT_CHECKS)},
        )
    )


@app.command()
def version() -> None:
    console.print(__version__)


async def _scan_async(
    domains: list[str],
    config: AppConfig,
    *,
    selected_checks: set[str],
    dkim_selectors: list[str],
    show_progress: bool,
) -> list[DomainScanResult]:
    async with MailGuardScanner(config) as scanner:
        if not show_progress:
            return await scanner.scan_many(
                domains,
                selected_checks=selected_checks,
                dkim_selectors=dkim_selectors,
            )
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Scanning domains", total=len(domains))

            def _advance(_: DomainScanResult) -> None:
                progress.advance(task_id)

            return await scanner.scan_many(
                domains,
                selected_checks=selected_checks,
                dkim_selectors=dkim_selectors,
                progress_callback=_advance,
            )


def _write_reports(
    generator: ReportGenerator,
    results: list[DomainScanResult],
    *,
    json_out: Path | None,
    csv_out: Path | None,
    html_out: Path | None,
) -> list[str]:
    errors: list[str] = []
    operations = [
        (json_out, generator.write_json, "JSON"),
        (csv_out, generator.write_csv, "CSV"),
        (html_out, generator.write_html, "HTML"),
    ]
    for destination, writer, label in operations:
        if destination is None:
            continue
        try:
            writer(results, destination)
        except Exception as exc:
            message = f"{label} export failed: {exc}"
            errors.append(message)
            console.print(f"[bold red]{message}[/bold red]")
    return errors


def _print_summary(results: list[DomainScanResult]) -> None:
    table = Table(title="MailGuard Summary")
    table.add_column("Domain")
    table.add_column("Risk")
    table.add_column("Grade")
    table.add_column("Critical/High")
    table.add_column("Top Recommendation")
    for result in results:
        critical_or_high = sum(1 for finding in result.findings if finding.severity in {Severity.CRITICAL, Severity.HIGH})
        recommendation = result.risk.recommendations[0] if result.risk.recommendations else "No urgent actions."
        table.add_row(result.domain, str(result.risk.score), result.risk.grade, str(critical_or_high), recommendation)
    console.print(table)


def _exit_code(results: list[DomainScanResult]) -> int:
    for result in results:
        if any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in result.findings):
            return 1
        if result.errors:
            return 1
    return 0
