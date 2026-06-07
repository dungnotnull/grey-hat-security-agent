"""VirusTotal API wrapper for domain and IP reputation.

Implements rate-limited API client (4 req/min free tier)
with SQLite response caching (24-hour TTL).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import aiohttp

from config.settings import settings
from utils.helpers import TokenBucketRateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)

# VirusTotal rate: 4 req/min, 500 req/day for free tier
_rate_limiter = TokenBucketRateLimiter(rate=4 / 60, capacity=4)

VT_API_BASE = "https://www.virustotal.com/api/v3"

# In-memory cache (keyed by URL hash, value = (data, expiry_time))
_cache: dict[str, tuple[dict, datetime]] = {}
_CACHE_TTL = timedelta(hours=24)


class VirusTotalClient:
    """Async rate-limited VirusTotal API client with caching."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.virustotal_api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            headers = {
                "x-apikey": self.api_key or "",
                "User-Agent": "grey-hat-security-agent/1.0",
            }
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=headers,
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    def _cache_key(self, endpoint: str, param: str) -> str:
        return hashlib.sha256(f"{endpoint}:{param}".encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[dict]:
        if key in _cache:
            data, expiry = _cache[key]
            if datetime.now(timezone.utc) < expiry:
                return data
            del _cache[key]
        return None

    def _set_cached(self, key: str, data: dict):
        _cache[key] = (data, datetime.now(timezone.utc) + _CACHE_TTL)

    async def get_domain_report(self, domain: str) -> Optional[dict]:
        """Get reputation report for a domain.

        Args:
            domain: Domain name to look up.

        Returns:
            Dict with detection stats, categories, and WHOIS info, or None.
        """
        cache_key = self._cache_key("domain", domain)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        if not self.api_key:
            logger.warning("VirusTotal API key not configured, skipping domain report")
            return None

        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            async with session.get(f"{VT_API_BASE}/domains/{domain}") as response:
                response.raise_for_status()
                return await response.json()

        try:
            data = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            total = sum(last_analysis.values())
            detection_ratio = last_analysis.get("malicious", 0) / max(total, 1)

            report = {
                "domain": domain,
                "detection_ratio": round(detection_ratio, 4),
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "undetected_count": last_analysis.get("undetected", 0),
                "harmless_count": last_analysis.get("harmless", 0),
                "total_engines": total,
                "categories": attrs.get("categories", []),
                "reputation": attrs.get("reputation", 0),
                "whois": attrs.get("whois", ""),
                "creation_date": attrs.get("creation_date", 0),
                "last_modification_date": attrs.get("last_modification_date", 0),
                "source": "virustotal",
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            self._set_cached(cache_key, report)
            return report
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(f"VirusTotal: domain {domain} not found")
                return None
            logger.error(f"VirusTotal domain report error for {domain}: {e}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal domain report failed for {domain}: {e}")
            return None

    async def get_ip_report(self, ip: str) -> Optional[dict]:
        """Get reputation report for an IP address."""
        cache_key = self._cache_key("ip", ip)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            async with session.get(f"{VT_API_BASE}/ip_addresses/{ip}") as response:
                response.raise_for_status()
                return await response.json()

        try:
            data = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})

            report = {
                "ip": ip,
                "detection_ratio": last_analysis.get("malicious", 0) / max(sum(last_analysis.values()), 1),
                "malicious_count": last_analysis.get("malicious", 0),
                "asn": attrs.get("asn", ""),
                "country": attrs.get("country", ""),
                "network": attrs.get("network", ""),
                "as_owner": attrs.get("as_owner", ""),
                "categories": attrs.get("categories", []),
                "source": "virustotal",
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            self._set_cached(cache_key, report)
            return report
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return None
            logger.error(f"VirusTotal IP report error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal IP report failed for {ip}: {e}")
            return None
