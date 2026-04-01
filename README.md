# MailGuard

MailGuard is a defensive email security assessment tool for validating domain mail posture at scale. It inspects DNS and SMTP controls that materially affect spoofing resistance, mail transport security, and operational hygiene, then produces structured results, risk scoring, and operator-friendly reports.

The current release covers:

- MX discovery and dangling MX / takeover-risk heuristics
- SPF parsing and lookup-budget validation
- DKIM selector discovery and weak-key detection
- DMARC policy and reporting validation
- BIMI record inspection with basic VMC retrieval/parsing
- MTA-STS and TLS-RPT discovery, retrieval, and policy validation
- SMTP security checks for STARTTLS, weak protocol/cipher exposure, downgrade risk, and safe relay behavior
- Optional MX IP reputation lookups through VirusTotal and AbuseIPDB
- JSON, CSV, and HTML reporting
- Monitoring mode with Slack and Telegram alerts

## Why MailGuard

MailGuard is designed for operators, security engineers, and platform teams who need repeatable validation of production email controls without stitching together multiple one-off scripts.

Key properties:

- Async architecture for batch-oriented scanning
- Typed configuration and models using Pydantic v2
- Modular analyzer layout for maintainability
- Practical CLI for one-time audits and recurring monitoring
- Structured outputs suitable for automation and reporting

## Use Cases

- Pre-production validation before onboarding or migrating mail infrastructure
- Periodic hygiene checks across managed domains
- Change verification after MX, SPF, DKIM, DMARC, or MTA-STS updates
- Operational monitoring with alerts for materially risky findings
- Internal security reviews and reporting workflows

## Ethical and Legal Use

MailGuard must only be used against infrastructure you own or are explicitly authorized to assess.

Important notes:

- SMTP relay checks use non-deliverable test addresses
- The tool does not send message bodies
- You remain responsible for local law, provider policy, and internal authorization

## Feature Set

### DNS and Policy Analysis

- `MX`: resolves MX targets, associated addresses, and suspicious alias patterns
- `SPF`: parses includes and redirects, tracks DNS lookup count, and flags permissive or broken policies
- `DKIM`: checks common selectors and estimates key length from published public keys
- `DMARC`: validates presence, policy mode, `pct`, and reporting configuration
- `BIMI`: checks record presence, HTTPS asset references, logo reachability, and basic VMC parsing
- `MTA-STS`: fetches and validates the HTTPS policy and verifies mode / MX coverage
- `TLS-RPT`: validates reporting record presence and `rua` targets

### SMTP Security Analysis

- STARTTLS advertisement and negotiation behavior
- Weak TLS protocol detection
- Weak cipher detection
- Downgrade exposure assessment when transport policy is not enforcing
- Safe unauthenticated relay behavior checks
- Basic `VRFY` / `EXPN` capability checks

### Reputation and Reporting

- VirusTotal IP reputation lookup for MX endpoints
- AbuseIPDB reputation lookup for MX endpoints
- Weighted domain risk scoring from `0-100`
- JSON output for automation
- CSV output for summary and reporting pipelines
- HTML output for human-readable review

### Monitoring

- Recurring rescans on a configurable interval
- Slack webhook alerts
- Telegram alerts
- Alerting based on critical/high findings or degraded risk score

## Architecture

```text
mailguard/
├── cli.py              # Typer CLI entrypoints
├── config.py           # Pydantic settings / config loading
├── scanner.py          # Scan orchestration
├── risk_score.py       # Weighted scoring logic
├── monitoring.py       # Periodic scanning loop
├── notifications.py    # Slack / Telegram alert delivery
├── analyzers/          # Protocol and control analyzers
├── core/               # DNS, HTTP, cache, rate-limit, utility helpers
└── reports/            # JSON/CSV/HTML report generation
```

The repository also keeps a compatibility launcher at the root:

- `mailguard.py`

## Installation

### Requirements

- Python 3.11+
- Network access to DNS, HTTPS, and optionally SMTP targets

### Install

```bash
pip install -r requirements.txt
```

Run the CLI with either:

```bash
python mailguard.py --help
```

## Configuration

MailGuard loads configuration from:

1. environment variables prefixed with `MAILGUARD_`
2. an optional `.env`
3. an optional TOML config file passed with `--config`
4. direct CLI overrides for selected fields

Example `mailguard.toml`:

```toml
concurrency = 100
cache_ttl = 300
cache_size = 50000
json_logs = false
log_level = "INFO"
dkim_selectors = ["default", "google", "selector1", "mail"]
virustotal_api_key = "VT_KEY"
abuseipdb_api_key = "ABUSE_KEY"
slack_webhook_url = "https://hooks.slack.com/services/..."
telegram_bot_token = "123456:ABCDEF"
telegram_chat_id = "123456789"
```

Common environment variables:

```bash
export MAILGUARD_VIRUSTOTAL_API_KEY=...
export MAILGUARD_ABUSEIPDB_API_KEY=...
export MAILGUARD_USE_TOR=true
export MAILGUARD_LOG_LEVEL=INFO
```

Relevant runtime settings:

- `concurrency`
- `dns_timeout`
- `http_timeout`
- `smtp_timeout`
- `cache_ttl`
- `cache_size`
- `dkim_selectors`
- `http_proxy`
- `https_proxy`
- `socks_proxy`
- `use_tor`
- `virustotal_api_key`
- `abuseipdb_api_key`
- `slack_webhook_url`
- `telegram_bot_token`
- `telegram_chat_id`

## Usage

### Basic Scan

```bash
python mailguard.py scan example.com
```

### Batch Scan

```bash
python mailguard.py scan domains.txt
python mailguard.py scan example.com example.org
python mailguard.py scan "example.com,example.org"
```

### Targeted Checks

```bash
python mailguard.py scan example.com --check mx --check spf --check dmarc
python mailguard.py scan example.com --check smtp --check mta-sts --check tls-rpt
python mailguard.py scan example.com --check bimi --check dmarc
```

### Custom DKIM Selectors

```bash
python mailguard.py scan example.com --dkim-selectors default,google,selector1
```

### Export Reports

```bash
python mailguard.py scan example.com --json-out reports/result.json
python mailguard.py scan example.com --csv-out reports/result.csv
python mailguard.py scan example.com --html-out reports/result.html
python mailguard.py scan example.com --json-out reports/result.json --csv-out reports/result.csv --html-out reports/result.html
```

### Monitoring Mode

```bash
python mailguard.py monitor example.com --interval 3600
python mailguard.py monitor domains.txt --interval 900 --cycles 4
python mailguard.py monitor example.com --interval 600 --check smtp --check mta-sts
```

### Tor / Proxy Support

```bash
python mailguard.py scan example.com --tor
```



## Output Formats

### JSON

Machine-readable full result set suitable for:

- automation
- pipelines
- post-processing
- alert enrichment

### CSV

Flattened executive summary suitable for:

- spreadsheets
- management reporting
- bulk result triage

### HTML

Human-readable report suitable for:

- security reviews
- ticket attachments
- audit evidence

## Monitoring and Alerting

`monitor` runs the same scan engine on a schedule and sends alerts when:

- risk score drops below `80`
- a finding is `critical`
- a finding is `high`

Supported notification channels:

- Slack webhook
- Telegram bot API

This mode is intended for operational hygiene, not for high-frequency active probing.

## Risk Scoring

MailGuard calculates a weighted domain score from `0-100`.

The current score model includes factors such as:

- missing or dangling MX
- invalid or permissive SPF
- weak or missing DKIM
- missing or non-enforcing DMARC
- missing or non-enforcing MTA-STS
- missing TLS-RPT
- SMTP downgrade or relay exposure
- negative MX IP reputation

The score is paired with:

- grade
- summary
- remediation recommendations

## VirusTotal and AbuseIPDB Integration

Reputation checks are optional and only run when API keys are configured.

Expected inputs:

- `MAILGUARD_VIRUSTOTAL_API_KEY`
- `MAILGUARD_ABUSEIPDB_API_KEY`

Current behavior:

- resolves public MX IPs
- queries reputation providers
- surfaces high-risk IPs in findings and score

## Production Notes

This repository is positioned as a production-oriented tool, but you should still treat the current release with the same controls you would apply to any security utility:

- run it from controlled environments
- validate SMTP behavior only against authorized targets
- protect API keys in environment variables or secret stores
- review HTML reports before external sharing if they contain internal domain inventory

Operational limitations to be aware of:

- SMTP certificate validation is currently basic and not equivalent to a full PKI trust evaluation
- common DKIM selectors are checked, but non-standard selectors require explicit input
- reputation lookups depend on external API availability and quota

## Development

### Run Tests

```bash
pytest
```

Current tests cover:

- risk scoring
- MTA-STS policy parsing
- HTML report rendering

### Project Structure

```text
MailGuard/
├── mailguard.py
├── requirements.txt
├── README.md
├── mailguard/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging_utils.py
│   ├── models.py
│   ├── scanner.py
│   ├── risk_score.py
│   ├── monitoring.py
│   ├── notifications.py
│   ├── core/
│   ├── analyzers/
│   └── reports/
└── tests/
```


## License
MIT
