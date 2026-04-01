from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, HttpUrl, PositiveInt, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Runtime configuration for MailGuard."""

    model_config = SettingsConfigDict(
        env_prefix="MAILGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "MailGuard"
    environment: Literal["development", "test", "production"] = "production"
    concurrency: PositiveInt = 100
    dns_timeout: float = 4.0
    http_timeout: float = 10.0
    smtp_timeout: float = 8.0
    api_timeout: float = 12.0
    http_max_connections: PositiveInt = 200
    cache_ttl: PositiveInt = 300
    cache_size: PositiveInt = 50_000
    dns_nameservers: list[str] = Field(default_factory=list)
    json_logs: bool = False
    log_level: str = "INFO"
    user_agent: str = "MailGuard/4.0"
    allow_private_mx_probe: bool = False
    rate_limit_per_second: float = 20.0
    api_rate_limit_per_second: float = 4.0
    smtp_max_hosts: PositiveInt = 3
    dkim_selectors: list[str] = Field(
        default_factory=lambda: [
            "default",
            "selector1",
            "selector2",
            "google",
            "googleworkspace",
            "k1",
            "mail",
            "smtp",
            "s1",
            "dkim",
        ]
    )
    bimi_selector: str = "default"
    http_proxy: str | None = None
    https_proxy: str | None = None
    socks_proxy: str | None = None
    use_tor: bool = False
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    slack_webhook_url: HttpUrl | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    default_output_dir: Path = Path("reports")
    verify_http_tls: bool = True
    report_title: str = "MailGuard Email Security Assessment"

    @field_validator("dns_nameservers", "dkim_selectors", mode="before")
    @classmethod
    def split_csv(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def normalize_proxy_settings(self) -> "AppConfig":
        if self.use_tor and not self.socks_proxy:
            self.socks_proxy = "socks5://127.0.0.1:9050"
        return self

    @property
    def effective_proxy(self) -> str | None:
        return self.socks_proxy or self.https_proxy or self.http_proxy

    @classmethod
    def load(cls, config_path: Path | None = None, **overrides: Any) -> "AppConfig":
        payload: dict[str, Any] = {}
        candidate = config_path or _default_config_path()
        if candidate and candidate.exists():
            with candidate.open("rb") as handle:
                payload = tomllib.load(handle)
        payload.update({key: value for key, value in overrides.items() if value is not None})
        return cls(**payload)


def _default_config_path() -> Path | None:
    env_value = os.getenv("MAILGUARD_CONFIG")
    if env_value:
        return Path(env_value)
    default = Path("mailguard.toml")
    return default if default.exists() else None
