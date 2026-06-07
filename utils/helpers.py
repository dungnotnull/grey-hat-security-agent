"""General helper utilities.

- Rate limiting (token bucket)
- Retry with exponential backoff
- Domain validation
- IP range parsing
- Timestamp formatting
"""

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Any

import ipaddress


# ---------------------------------------------------------------------------
# Rate Limiter (Token Bucket)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Async token bucket rate limiter for API calls."""

    def __init__(self, rate: float, capacity: int):
        """Initialize rate limiter.

        Args:
            rate: Tokens added per second.
            capacity: Maximum burst size.
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        """Try to acquire one token. Returns True if available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self._last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    async def wait_and_acquire(self, max_wait: float = 30.0) -> bool:
        """Wait until a token is available, then acquire it.

        Args:
            max_wait: Maximum seconds to wait. Returns False if exceeded.

        Returns:
            True if token acquired, False if max_wait exceeded.
        """
        deadline = time.monotonic() + max_wait
        while True:
            if await self.acquire():
                return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(min(1.0 / self.rate, 0.5))


# Pre-configured rate limiters per service
RATE_LIMITERS = {
    "virustotal": TokenBucketRateLimiter(rate=4 / 60, capacity=4),
    "shodan": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "nvd": TokenBucketRateLimiter(rate=50 / 30, capacity=10),
    "phishtank": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "urlhaus": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "openphish": TokenBucketRateLimiter(rate=1.0, capacity=1),
}


# ---------------------------------------------------------------------------
# Retry with Exponential Backoff
# ---------------------------------------------------------------------------

async def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
) -> Any:
    """Retry an async function with exponential backoff.

    Args:
        func: Async callable to retry.
        max_retries: Maximum number of retries.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay between retries.
        exceptions: Tuple of exception types to catch.

    Returns:
        Result of func().

    Raises:
        Last exception if all retries fail.
    """
    last_exception = None
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                await asyncio.sleep(delay)
    raise last_exception


# ---------------------------------------------------------------------------
# Domain Validation
# ---------------------------------------------------------------------------

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    return bool(DOMAIN_REGEX.match(domain))


def is_valid_ip(ip_str: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# IP Range Parsing
# ---------------------------------------------------------------------------

def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR range to a list of IP addresses.

    Only expands /24 or smaller ranges to avoid huge lists.
    For larger ranges, returns the network address and broadcast address.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        List of IP address strings.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses <= 256:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address), str(network.broadcast_address)]
    except ValueError:
        return []


def ip_in_range(ip_str: str, cidr_ranges: list[str]) -> bool:
    """Check if an IP address is within any of the given CIDR ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidr_ranges:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Timestamp Formatting
# ---------------------------------------------------------------------------

def format_timestamp(unix_ts: int) -> str:
    """Format a Unix timestamp to ISO 8601 string."""
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()


def parse_iso_timestamp(iso_str: str) -> int:
    """Parse an ISO 8601 timestamp to Unix timestamp."""
    dt = datetime.fromisoformat(iso_str)
    return int(dt.timestamp())


def iso_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
