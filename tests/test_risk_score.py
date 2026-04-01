from mailguard.models import DMARCAnalysis, DomainScanResult, MXHost, SPFAnalysis, Status
from mailguard.risk_score import assess_risk


def test_risk_score_penalizes_missing_controls() -> None:
    result = DomainScanResult(domain="example.com")
    result.mx = [MXHost(hostname="mail.example.com", priority=10, addresses=["203.0.113.10"], status=Status.PASS)]
    result.spf = SPFAnalysis(present=False, status=Status.FAIL)
    result.dmarc = DMARCAnalysis(present=False, status=Status.FAIL)
    assessment = assess_risk(result)
    assert assessment.score < 70
    assert assessment.grade in {"D", "F"}
    assert any(factor.code == "spf_missing_or_invalid" for factor in assessment.factors)
    assert any(factor.code == "dmarc_missing" for factor in assessment.factors)
