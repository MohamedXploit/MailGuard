from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


ETHICAL_WARNING = (
    "Use MailGuard only against infrastructure you own or are explicitly authorized to assess. "
    "SMTP relay probes use non-deliverable test addresses and avoid transmitting message bodies."
)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    ERROR = "error"
    SKIPPED = "skipped"


class MailGuardBaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class Finding(MailGuardBaseModel):
    code: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    evidence: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class DNSCacheStats(MailGuardBaseModel):
    size: int = 0
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    hit_rate: float = 0.0


class MXHost(MailGuardBaseModel):
    hostname: str
    priority: int
    addresses: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    dangling: bool = False
    takeover_suspected: bool = False
    takeover_provider: str | None = None
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class SPFAnalysis(MailGuardBaseModel):
    present: bool = False
    record: str | None = None
    includes: list[str] = Field(default_factory=list)
    redirects: list[str] = Field(default_factory=list)
    lookup_count: int = 0
    all_qualifier: str | None = None
    recursion_chain: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class DKIMKey(MailGuardBaseModel):
    selector: str
    record_name: str
    present: bool = False
    key_type: str | None = None
    key_length: int | None = None
    hash_algorithms: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class DKIMAnalysis(MailGuardBaseModel):
    selectors_tested: list[str] = Field(default_factory=list)
    keys: list[DKIMKey] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class DMARCAnalysis(MailGuardBaseModel):
    present: bool = False
    record: str | None = None
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int = 100
    rua: list[str] = Field(default_factory=list)
    ruf: list[str] = Field(default_factory=list)
    adkim: str | None = None
    aspf: str | None = None
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class VMCCertificate(MailGuardBaseModel):
    url: str
    fetched: bool = False
    parsed: bool = False
    valid_format: bool = False
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    expires_at: datetime | None = None
    errors: list[str] = Field(default_factory=list)


class BIMIAnalysis(MailGuardBaseModel):
    selector: str = "default"
    present: bool = False
    record_name: str | None = None
    record: str | None = None
    logo_url: str | None = None
    authority_url: str | None = None
    logo_accessible: bool = False
    vmc: VMCCertificate | None = None
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class MTASTSPolicy(MailGuardBaseModel):
    version: str | None = None
    mode: str | None = None
    max_age: int | None = None
    mx_patterns: list[str] = Field(default_factory=list)
    raw_policy: str | None = None
    valid: bool = False
    issues: list[str] = Field(default_factory=list)


class MTASTSAnalysis(MailGuardBaseModel):
    present: bool = False
    dns_record: str | None = None
    policy_id: str | None = None
    policy_url: str | None = None
    fetch_status: int | None = None
    policy: MTASTSPolicy | None = None
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class TLSRPTAnalysis(MailGuardBaseModel):
    present: bool = False
    record: str | None = None
    rua: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class TLSProbe(MailGuardBaseModel):
    host: str
    port: int = 25
    banner: str | None = None
    starttls_advertised: bool = False
    starttls_successful: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expires_at: datetime | None = None
    certificate_valid: bool = False
    certificate_errors: list[str] = Field(default_factory=list)
    weak_cipher: bool = False
    weak_protocol: bool = False
    downgrade_possible: bool = False
    open_relay_suspected: bool = False
    open_relay_evidence: list[str] = Field(default_factory=list)
    vrfy_enabled: bool = False
    expn_enabled: bool = False
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class SMTPAnalysis(MailGuardBaseModel):
    hosts: list[TLSProbe] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.INFO


class IPReputation(MailGuardBaseModel):
    ip: str
    provider: str
    malicious: int | None = None
    suspicious: int | None = None
    abuse_confidence_score: int | None = None
    country: str | None = None
    last_analysis_date: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    status: Status = Status.INFO


class ReputationAnalysis(MailGuardBaseModel):
    hosts: dict[str, list[IPReputation]] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)
    status: Status = Status.SKIPPED


class RiskFactor(MailGuardBaseModel):
    code: str
    severity: Severity
    weight: int
    penalty: int
    description: str
    recommendation: str


class RiskAssessment(MailGuardBaseModel):
    score: int = 100
    grade: str = "A"
    summary: str = "No material issues detected."
    factors: list[RiskFactor] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class DomainScanResult(MailGuardBaseModel):
    domain: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ethical_warning: str = ETHICAL_WARNING
    mx: list[MXHost] = Field(default_factory=list)
    spf: SPFAnalysis = Field(default_factory=SPFAnalysis)
    dkim: DKIMAnalysis = Field(default_factory=DKIMAnalysis)
    dmarc: DMARCAnalysis = Field(default_factory=DMARCAnalysis)
    bimi: BIMIAnalysis = Field(default_factory=BIMIAnalysis)
    mta_sts: MTASTSAnalysis = Field(default_factory=MTASTSAnalysis)
    tls_rpt: TLSRPTAnalysis = Field(default_factory=TLSRPTAnalysis)
    smtp: SMTPAnalysis = Field(default_factory=SMTPAnalysis)
    reputation: ReputationAnalysis = Field(default_factory=ReputationAnalysis)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    dns_cache: DNSCacheStats | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(MailGuardBaseModel):
    scanned_domains: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    average_risk_score: float
    critical_findings: int
    high_findings: int
    warning_findings: int
    ethical_warning: str = ETHICAL_WARNING
