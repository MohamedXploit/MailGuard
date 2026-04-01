from mailguard.config import AppConfig
from mailguard.models import DomainScanResult
from mailguard.reports.generator import ReportGenerator


def test_render_html_contains_domain() -> None:
    generator = ReportGenerator(AppConfig())
    html = generator.render_html([DomainScanResult(domain="example.com")])
    assert "example.com" in html
    assert "MailGuard" in html
