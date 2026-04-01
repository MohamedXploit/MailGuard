from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from mailguard.config import AppConfig
from mailguard.core.rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


class AsyncHTTPClient:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.rate_limiter = AsyncRateLimiter(config.http_max_connections, config.rate_limit_per_second)
        self.api_rate_limiter = AsyncRateLimiter(max(4, config.http_max_connections // 4), config.api_rate_limit_per_second)
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AsyncHTTPClient":
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.http_timeout),
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True,
            proxy=self.config.effective_proxy,
            verify=self.config.verify_http_tls,
            limits=httpx.Limits(
                max_connections=self.config.http_max_connections,
                max_keepalive_connections=max(20, self.config.http_max_connections // 2),
            ),
        )
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.client is not None:
            await self.client.aclose()

    async def get(self, url: str, *, headers: dict[str, str] | None = None, is_api: bool = False) -> httpx.Response:
        return await self._request("GET", url, headers=headers, is_api=is_api)

    async def head(self, url: str, *, headers: dict[str, str] | None = None, is_api: bool = False) -> httpx.Response:
        return await self._request("HEAD", url, headers=headers, is_api=is_api)

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        is_api: bool = False,
    ) -> httpx.Response:
        return await self._request("POST", url, headers=headers, json=json, data=data, is_api=is_api)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self.client is None:
            raise RuntimeError("HTTP client must be used as an async context manager.")
        is_api = kwargs.pop("is_api", False)
        limiter = self.api_rate_limiter if is_api else self.rate_limiter
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with limiter.limit("api" if is_api else "http"):
                    response = await self.client.request(method, url, **kwargs)
                return response
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_error = exc
                await asyncio.sleep(0.4 * (attempt + 1))
        raise RuntimeError(f"HTTP request failed for {url}: {last_error}") from last_error
