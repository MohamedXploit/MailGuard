from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable


def normalize_domain(value: str) -> str:
    cleaned = value.strip().lower()
    cleaned = cleaned.removeprefix("https://").removeprefix("http://")
    cleaned = cleaned.split("/")[0]
    return cleaned.rstrip(".")


def parse_domain_sources(inputs: Iterable[str]) -> list[str]:
    domains: list[str] = []
    for item in inputs:
        candidate = Path(item)
        if candidate.exists() and candidate.is_file():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(normalize_domain(line))
            continue
        domains.extend(normalize_domain(part) for part in item.split(",") if part.strip())
    return sorted({domain for domain in domains if domain})


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_multicast,
            ip.is_link_local,
            ip.is_reserved,
            ip.is_unspecified,
        ]
    )


def flatten_tag_value(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
