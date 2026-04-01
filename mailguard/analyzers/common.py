from __future__ import annotations

import base64


def parse_tag_pairs(record: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        pairs[key.strip().lower()] = value.strip()
    return pairs


def estimate_b64_key_bits(value: str) -> int | None:
    if not value:
        return None
    normalized = value.strip()
    missing_padding = len(normalized) % 4
    if missing_padding:
        normalized += "=" * (4 - missing_padding)
    try:
        decoded = base64.b64decode(normalized.encode("ascii"), validate=False)
    except Exception:
        return None
    return len(decoded) * 8 if decoded else None
