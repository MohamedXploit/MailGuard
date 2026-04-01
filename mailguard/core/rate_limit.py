from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import AsyncIterator


class AsyncRateLimiter:
    def __init__(self, max_concurrency: int, rate_per_second: float) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rate = rate_per_second
        self._lock = asyncio.Lock()
        self._last_called: dict[str, float] = defaultdict(float)

    @asynccontextmanager
    async def limit(self, key: str = "default") -> AsyncIterator[None]:
        await self._semaphore.acquire()
        try:
            await self._throttle(key)
            yield
        finally:
            self._semaphore.release()

    async def _throttle(self, key: str) -> None:
        if self._rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_called[key]
            min_interval = 1.0 / self._rate
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_called[key] = time.monotonic()
