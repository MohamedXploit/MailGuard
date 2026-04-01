from __future__ import annotations

from collections import OrderedDict

from mailguard.models import DomainScanResult, RiskAssessment, RiskFactor, Severity, Status


def assess_risk(result: DomainScanResult) -> RiskAssessment:
    factors: list[RiskFactor] = []
    if _scanned(result, "mx"):
        if not result.mx:
            factors.append(_factor("mx_missing", Severity.HIGH, 20, 20, "No MX records were found.", "Publish explicit MX records if the domain should receive mail."))
        elif any(item.dangling for item in result.mx):
            factors.append(_factor("mx_dangling", Severity.CRITICAL, 20, 20, "Dangling MX targets were detected.", "Remove stale MX entries or restore the referenced hosts."))
    if _scanned(result, "spf"):
        if result.spf.status == Status.FAIL or not result.spf.present:
            factors.append(_factor("spf_missing_or_invalid", Severity.HIGH, 15, 15, "SPF is missing or invalid.", "Publish a single valid SPF record with a bounded lookup chain."))
        elif result.spf.all_qualifier == "~":
            factors.append(_factor("spf_softfail", Severity.MEDIUM, 8, 8, "SPF is configured as softfail.", "Move SPF to -all when rollout is complete."))
        if result.spf.lookup_count > 10:
            factors.append(_factor("spf_lookup_limit", Severity.HIGH, 10, 10, "SPF exceeds the 10 lookup RFC limit.", "Flatten or simplify SPF includes and redirects."))
    if _scanned(result, "dkim"):
        if not result.dkim.keys:
            factors.append(_factor("dkim_missing", Severity.MEDIUM, 10, 10, "No DKIM selectors were found in the tested set.", "Publish 2048-bit DKIM selectors and verify active selector names."))
        elif any(key.key_length and key.key_length < 2048 for key in result.dkim.keys):
            factors.append(_factor("dkim_weak", Severity.HIGH, 12, 12, "Weak DKIM key material was detected.", "Rotate DKIM selectors to 2048-bit RSA or stronger."))
    if _scanned(result, "dmarc"):
        if not result.dmarc.present:
            factors.append(_factor("dmarc_missing", Severity.CRITICAL, 20, 20, "DMARC is missing.", "Publish DMARC and progress toward enforcement."))
        elif result.dmarc.policy == "none":
            factors.append(_factor("dmarc_none", Severity.HIGH, 15, 15, "DMARC is monitor-only.", "Move DMARC to quarantine or reject after validating mail flows."))
        if result.dmarc.present and result.dmarc.pct < 100:
            factors.append(_factor("dmarc_partial", Severity.MEDIUM, 5, 5, "DMARC enforcement is partial.", "Increase pct to 100 when rollout is complete."))
    if _scanned(result, "bimi") and result.bimi.present and (not result.bimi.logo_accessible or (result.bimi.vmc and result.bimi.vmc.errors)):
        factors.append(_factor("bimi_invalid", Severity.LOW, 4, 4, "BIMI is published but incomplete or invalid.", "Fix the BIMI logo and VMC assets before relying on brand indicators."))
    if _scanned(result, "mta-sts"):
        if not result.mta_sts.present:
            factors.append(_factor("mta_sts_missing", Severity.MEDIUM, 8, 8, "MTA-STS is missing.", "Deploy MTA-STS in testing mode first, then move to enforce."))
        elif result.mta_sts.policy and result.mta_sts.policy.mode != "enforce":
            factors.append(_factor("mta_sts_not_enforcing", Severity.MEDIUM, 5, 5, "MTA-STS is not enforcing.", "Move MTA-STS to enforce after validating MX coverage and TLS readiness."))
    if _scanned(result, "tls-rpt") and not result.tls_rpt.present:
        factors.append(_factor("tls_rpt_missing", Severity.LOW, 3, 3, "TLS-RPT is missing.", "Publish TLS-RPT so mail transport failures are reported."))
    if _scanned(result, "smtp"):
        if any(item.open_relay_suspected for item in result.smtp.hosts):
            factors.append(_factor("smtp_open_relay", Severity.CRITICAL, 25, 25, "An MX host appears to relay unauthenticated external mail.", "Disable relay behavior immediately and restrict SMTP submission paths."))
        if any(not item.starttls_advertised for item in result.smtp.hosts):
            factors.append(_factor("smtp_no_starttls", Severity.HIGH, 15, 15, "At least one MX host does not advertise STARTTLS.", "Enable STARTTLS on all MX hosts and validate certificates."))
        if any(item.weak_protocol or item.weak_cipher for item in result.smtp.hosts):
            factors.append(_factor("smtp_weak_tls", Severity.HIGH, 10, 10, "Weak TLS protocol or cipher negotiation was detected.", "Disable legacy TLS versions and weak cipher suites on MX hosts."))
        if any(item.downgrade_possible for item in result.smtp.hosts):
            factors.append(_factor("smtp_downgrade", Severity.MEDIUM, 8, 8, "Mail transport is still vulnerable to downgrade or STARTTLS stripping scenarios.", "Combine enforced MTA-STS with reliable STARTTLS coverage."))
    if _scanned(result, "reputation") and result.reputation.status == Status.WARN:
        factors.append(_factor("mx_reputation", Severity.HIGH, 10, 10, "External intelligence flagged one or more MX IPs.", "Review the affected MX hosts for compromise or abuse history."))
    total_penalty = sum(item.penalty for item in factors)
    score = max(0, 100 - total_penalty)
    grade = _grade(score)
    summary = _summary(score)
    recommendations = list(OrderedDict.fromkeys(item.recommendation for item in sorted(factors, key=lambda item: item.penalty, reverse=True)))
    return RiskAssessment(score=score, grade=grade, summary=summary, factors=factors, recommendations=recommendations)


def _scanned(result: DomainScanResult, check: str) -> bool:
    selected = {item.lower() for item in result.metadata.get("selected_checks", [])}
    return check.lower() in selected if selected else True


def _factor(code: str, severity: Severity, weight: int, penalty: int, description: str, recommendation: str) -> RiskFactor:
    return RiskFactor(
        code=code,
        severity=severity,
        weight=weight,
        penalty=penalty,
        description=description,
        recommendation=recommendation,
    )


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _summary(score: int) -> str:
    if score >= 90:
        return "Low risk posture with minor hardening opportunities."
    if score >= 80:
        return "Generally healthy posture with several improvements still recommended."
    if score >= 70:
        return "Moderate risk posture; prioritized remediation is recommended."
    if score >= 60:
        return "Elevated risk posture with meaningful exposure across email controls."
    return "High risk posture requiring urgent remediation."
