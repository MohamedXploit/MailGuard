from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Generic, TypeVar

from mailguard.models import DNSCacheStats

T = TypeVar("T")


@dataclass(slots=True)
class CacheEntry(Generic[T]):
    value: T
    expires_at: float


class TTLCache(Generic[T]):
    def __init__(self, ttl: int, max_size: int) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._lock = asyncio.Lock()
        self._data: dict[str, CacheEntry[T]] = {}
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0

    async def get(self, key: str) -> T | None:
        async with self._lock:
            entry = self._data.get(key)
            if not entry:
                self.misses += 1
                return None
            if entry.expires_at <= time.monotonic():
                self.expirations += 1
                self.misses += 1
                self._data.pop(key, None)
                return None
            self.hits += 1
            return entry.value

    async def set(self, key: str, value: T, ttl: int | None = None) -> None:
        async with self._lock:
            await self._evict_if_needed()
            lifetime = ttl if ttl and ttl > 0 else self._ttl
            self._data[key] = CacheEntry(value=value, expires_at=time.monotonic() + lifetime)

    async def _evict_if_needed(self) -> None:
        if len(self._data) < self._max_size:
            return
        now = time.monotonic()
        expired = [key for key, entry in self._data.items() if entry.expires_at <= now]
        for key in expired:
            self._data.pop(key, None)
            self.expirations += 1
        if len(self._data) < self._max_size:
            return
        oldest_keys = sorted(self._data, key=lambda item: self._data[item].expires_at)[: max(1, self._max_size // 10)]
        for key in oldest_keys:
            self._data.pop(key, None)
            self.evictions += 1

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    def stats(self) -> DNSCacheStats:
        total = self.hits + self.misses
        hit_rate = round((self.hits / total) * 100, 2) if total else 0.0
        return DNSCacheStats(
            size=len(self._data),
            hits=self.hits,
            misses=self.misses,
            evictions=self.evictions,
            expirations=self.expirations,
            hit_rate=hit_rate,
        )
