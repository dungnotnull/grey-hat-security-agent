"""URLhaus API client for malware URL intelligence.

Queries URLhaus REST API for domain-to-malware-URL associations
and bulk downloads recent malicious URLs.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from utils.helpers import TokenBucketRateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)

_rate_limiter = TokenBucketRateLimiter(rate=1.0, capacity=1)

URLHAUS_API_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausClient:
    """Async client for URLhaus malware URL database."""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "grey-hat-security-agent/1.0"},
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def query_host(self, host: str) -> list[dict]:
        """Query URLs for a specific host.

        Args:
            host: Domain name or IP address.

        Returns:
            List of URLhaus entries for this host.
        """
        await _rate_limiter.wait_and_acquire()

        async def _query():
            session = await self._get_session()
            payload = {"host": host}
            async with session.post(f"{URLHAUS_API_BASE}/urls/host/", data=payload) as response:
                response.raise_for_status()
                return await response.json(content_type=None)

        try:
            data = await retry_with_backoff(_query, max_retries=3, exceptions=(aiohttp.ClientError,))
            urls = data.get("urls", [])
            entries = []
            for item in urls:
                entries.append({
                    "url": item.get("url", ""),
                    "threat": item.get("threat", ""),
                    "tags": item.get("tags", []),
                    "url_status": item.get("url_status", ""),
                    "date_added": item.get("date_added", ""),
                    "host": host,
                    "source": "urlhaus",
                })
            return entries
        except Exception as e:
            logger.error(f"URLhaus host query failed for {host}: {e}")
            return []

    async def fetch_recent(self, limit: int = 100) -> list[dict]:
        """Fetch recent malicious URLs from URLhaus.

        Args:
            limit: Maximum number of entries to fetch.

        Returns:
            List of recent URLhaus entries.
        """
        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            payload = {"limit": str(limit)}
            async with session.post(f"{URLHAUS_API_BASE}/urls/", data=payload) as response:
                response.raise_for_status()
                return await response.json(content_type=None)

        try:
            data = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))
            urls = data.get("urls", [])
            entries = []
            for item in urls:
                entries.append({
                    "url": item.get("url", ""),
                    "threat": item.get("threat", ""),
                    "tags": item.get("tags", []),
                    "url_status": item.get("url_status", ""),
                    "date_added": item.get("date_added", ""),
                    "host": item.get("host", ""),
                    "source": "urlhaus",
                })
            logger.info(f"URLhaus: fetched {len(entries)} recent entries")
            return entries
        except Exception as e:
            logger.error(f"URLhaus recent fetch failed: {e}")
            return []
