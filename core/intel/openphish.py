"""OpenPhish feed downloader and parser.

Fetches the OpenPhish community feed (plain text URLs),
parses domains, and deduplicates against local cache.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from utils.helpers import TokenBucketRateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)

_rate_limiter = TokenBucketRateLimiter(rate=1.0, capacity=1)

OPENPHISH_COMMUNITY_URL = "https://www.openphish.com/feed.txt"


class OpenPhishClient:
    """Async client for OpenPhish community phishing feed."""

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

    async def fetch_recent(self) -> list[dict]:
        """Fetch recent phishing URLs from OpenPhish community feed.

        Returns:
            List of entry dicts with keys: url, domain, source
        """
        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            async with session.get(OPENPHISH_COMMUNITY_URL) as response:
                response.raise_for_status()
                text = await response.text()
                return text

        try:
            text = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))
            entries = []
            seen_domains = set()

            for line in text.strip().splitlines():
                url = line.strip()
                if not url:
                    continue

                parsed = urlparse(url)
                domain = parsed.hostname or parsed.netloc
                if not domain:
                    continue

                # Deduplicate domains within this batch
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)

                entries.append({
                    "url": url,
                    "domain": domain,
                    "source": "openphish",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                })

            logger.info(f"OpenPhish: fetched {len(entries)} unique domain entries")
            return entries
        except Exception as e:
            logger.error(f"OpenPhish fetch failed: {e}")
            return []
