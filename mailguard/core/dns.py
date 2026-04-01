from __future__ import annotations

import asyncio
import logging
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from mailguard.config import AppConfig
from mailguard.core.cache import TTLCache
from mailguard.core.rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


class AsyncDNSClient:
    def __init__(self, config: AppConfig, cache: TTLCache[list[str]] | None = None) -> None:
        self.config = config
        self.cache = cache
        self.rate_limiter = AsyncRateLimiter(config.concurrency, config.rate_limit_per_second)
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.lifetime = config.dns_timeout
        self.resolver.timeout = config.dns_timeout
        if config.dns_nameservers:
            self.resolver.nameservers = config.dns_nameservers

    async def query(self, name: str, rdtype: str) -> list[str]:
        cache_key = f"{name}:{rdtype}"
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached
        async with self.rate_limiter.limit("dns"):
            try:
                answer = await self.resolver.resolve(
                    qname=name,
                    rdtype=rdtype,
                    raise_on_no_answer=False,
                    lifetime=self.config.dns_timeout,
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                records: list[str] = []
            except dns.exception.Timeout:
                logger.warning("DNS timeout for %s %s", name, rdtype)
                records = []
            except Exception as exc:
                logger.debug("Unexpected DNS error for %s %s: %s", name, rdtype, exc)
                records = []
            else:
                if not answer.rrset:
                    records = []
                else:
                    records = [self._normalize_record_text(item, rdtype) for item in answer]
                    ttl = getattr(answer.rrset, "ttl", self.config.cache_ttl)
                    if self.cache:
                        await self.cache.set(cache_key, records, ttl=ttl)
                    return records
        if self.cache:
            await self.cache.set(cache_key, records, ttl=self.config.cache_ttl)
        return records

    async def resolve_txt(self, name: str) -> list[str]:
        return await self.query(name, "TXT")

    async def resolve_mx(self, domain: str) -> list[tuple[int, str]]:
        raw = await self.query(domain, "MX")
        results: list[tuple[int, str]] = []
        for record in raw:
            try:
                priority, host = record.split(maxsplit=1)
                results.append((int(priority), host.rstrip(".")))
            except ValueError:
                continue
        return sorted(results, key=lambda item: item[0])

    async def resolve_a(self, host: str) -> list[str]:
        return await self.query(host, "A")

    async def resolve_aaaa(self, host: str) -> list[str]:
        return await self.query(host, "AAAA")

    async def resolve_cname(self, host: str) -> list[str]:
        return await self.query(host, "CNAME")

    async def resolve_addresses(self, host: str) -> list[str]:
        a_records, aaaa_records = await asyncio.gather(self.resolve_a(host), self.resolve_aaaa(host))
        return [*a_records, *aaaa_records]

    @staticmethod
    def _normalize_record_text(record: Any, rdtype: str) -> str:
        if rdtype.upper() == "TXT":
            if hasattr(record, "strings"):
                return "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in record.strings
                )
            return record.to_text().strip('"')
        if rdtype.upper() == "MX":
            preference = getattr(record, "preference", None)
            exchange = getattr(record, "exchange", None)
            if preference is not None and exchange is not None:
                return f"{preference} {str(exchange).rstrip('.')}"
        return record.to_text().rstrip(".")
