"""Shodan API client for IP service enumeration.

Queries Shodan for open ports, service banners, and
known vulnerabilities on target IPs.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

from config.settings import settings
from utils.helpers import TokenBucketRateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)

_rate_limiter = TokenBucketRateLimiter(rate=1.0, capacity=1)

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanClient:
    """Async rate-limited Shodan API client."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.shodan_api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def get_host(self, ip: str) -> Optional[dict]:
        """Get Shodan host information for an IP.

        Args:
            ip: IP address to look up.

        Returns:
            Dict with ports, banners, vulnerabilities, or None.
        """
        if not self.api_key:
            logger.warning("Shodan API key not configured")
            return None

        await _rate_limiter.wait_and_acquire()

        async def _fetch():
            session = await self._get_session()
            params = {"key": self.api_key}
            async with session.get(f"{SHODAN_API_BASE}/shodan/host/{ip}", params=params) as response:
                response.raise_for_status()
                return await response.json()

        try:
            data = await retry_with_backoff(_fetch, max_retries=3, exceptions=(aiohttp.ClientError,))

            services = []
            for item in data.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "service": item.get("_shodan", {}).get("module", ""),
                    "banner": item.get("data", "")[:500],  # Truncate long banners
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "cpe": item.get("cpe", []),
                })

            report = {
                "ip": ip,
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "os": data.get("os", ""),
                "ports": data.get("ports", []),
                "services": services,
                "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                "source": "shodan",
            }
            return report
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(f"Shodan: no data for {ip}")
                return None
            logger.error(f"Shodan host query error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Shodan host query failed for {ip}: {e}")
            return None
