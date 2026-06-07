"""PhishTank feed downloader and parser.

Downloads phishing URL data from PhishTank API, deduplicates
against SQLite cache, and queues novel entries for enrichment.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from config.settings import settings
from utils.helpers import TokenBucketRateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)

# Rate limiter: 1 request per second
_rate_limiter = TokenBucketRateLimiter(rate=1.0, capacity=1)

PHISHTANK_API_BASE = "https://data.phishtank.com/data"


class PhishTankClient:
    """Async client for PhishTank phishing data."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.phishtank_api_key
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
        """Fetch recent phishing URLs from PhishTank.

        Returns:
            List of phishing entry dicts with keys:
            url, phish_id, target, online, submission_time, verification_time
        """
        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            url = f"{PHISHTANK_API_BASE}/online-valid.json"
            if self.api_key:
                url = f"{PHISHTANK_API_BASE}/{self.api_key}/online-valid.json"

            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json(content_type=None)
                return data

        try:
            data = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))
            entries = []
            for item in data:
                entry = {
                    "url": item.get("url", ""),
                    "phish_id": item.get("phish_id", ""),
                    "target_brand": item.get("target", ""),
                    "online": item.get("online", False),
                    "submission_time": item.get("submission", {}).get("time", "") if isinstance(item.get("submission"), dict) else "",
                    "verification_time": item.get("verification_time", ""),
                    "details_url": item.get("phish_detail_url", ""),
                    "source": "phishtank",
                }
                entries.append(entry)
            logger.info(f"PhishTank: fetched {len(entries)} entries")
            return entries
        except Exception as e:
            logger.error(f"PhishTank fetch failed: {e}")
            return []

    async def check_url(self, url: str) -> Optional[dict]:
        """Check if a URL is in PhishTank database.

        Args:
            url: URL to check.

        Returns:
            PhishTank entry if found, None otherwise.
        """
        await _rate_limiter.wait_and_acquire()

        try:
            session = await self._get_session()
            check_url = "https://checkurl.phishtank.com/checkurl/"
            if self.api_key:
                payload = {"url": url, "app_key": self.api_key, "format": "json"}
            else:
                payload = {"url": url, "format": "json"}

            async with session.post(check_url, data=payload) as response:
                response.raise_for_status()
                data = await response.json(content_type=None)
                if data.get("results", {}).get("in_database", False):
                    return data["results"]
                return None
        except Exception as e:
            logger.error(f"PhishTank check failed for {url}: {e}")
            return None
