from __future__ import annotations

import csv
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from mailguard.config import AppConfig
from mailguard.models import DomainScanResult, ScanSummary, Severity


class ReportGenerator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        template_root = Path(__file__).resolve().parent / "templates"
        self.environment = Environment(
            loader=FileSystemLoader(str(template_root)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build_summary(self, results: list[DomainScanResult]) -> ScanSummary:
        critical = sum(1 for result in results for finding in result.findings if finding.severity == Severity.CRITICAL)
        high = sum(1 for result in results for finding in result.findings if finding.severity == Severity.HIGH)
        warning_findings = sum(1 for result in results for finding in result.findings if finding.severity in {Severity.MEDIUM, Severity.LOW})
        average = round(sum(result.risk.score for result in results) / len(results), 2) if results else 0.0
        return ScanSummary(
            scanned_domains=len(results),
            average_risk_score=average,
            critical_findings=critical,
            high_findings=high,
            warning_findings=warning_findings,
        )

    def write_json(self, results: list[DomainScanResult], destination: Path) -> None:
        self._ensure_parent(destination)
        payload = {
            "summary": self.build_summary(results).model_dump(mode="json"),
            "results": [result.model_dump(mode="json") for result in results],
        }
        destination.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def write_csv(self, results: list[DomainScanResult], destination: Path) -> None:
        self._ensure_parent(destination)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "domain",
                    "risk_score",
                    "grade",
                    "mx_hosts",
                    "spf_status",
                    "dmarc_policy",
                    "bimi_present",
                    "mta_sts_mode",
                    "tls_rpt_present",
                    "smtp_status",
                    "critical_findings",
                    "high_findings",
                ],
            )
            writer.writeheader()
            for result in results:
                writer.writerow(
                    {
                        "domain": result.domain,
                        "risk_score": result.risk.score,
                        "grade": result.risk.grade,
                        "mx_hosts": ", ".join(host.hostname for host in result.mx),
                        "spf_status": result.spf.status.value,
                        "dmarc_policy": result.dmarc.policy,
                        "bimi_present": result.bimi.present,
                        "mta_sts_mode": result.mta_sts.policy.mode if result.mta_sts.policy else None,
                        "tls_rpt_present": result.tls_rpt.present,
                        "smtp_status": result.smtp.status.value,
                        "critical_findings": sum(1 for finding in result.findings if finding.severity == Severity.CRITICAL),
                        "high_findings": sum(1 for finding in result.findings if finding.severity == Severity.HIGH),
                    }
                )

    def render_html(self, results: list[DomainScanResult]) -> str:
        template = self.environment.get_template("report.html.j2")
        return template.render(
            title=self.config.report_title,
            summary=self.build_summary(results),
            results=results,
            generated_for=self.config.app_name,
        )

    def write_html(self, results: list[DomainScanResult], destination: Path) -> None:
        self._ensure_parent(destination)
        destination.write_text(self.render_html(results), encoding="utf-8")

    @staticmethod
    def _ensure_parent(destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
