"""Token bucket rate limiter for API calls.

Implements per-service rate limiting:
- VirusTotal: 4 req/min, 500 req/day
- Shodan: 1 req/sec
- NVD: 50 req/30sec (with key), 5 req/30sec (without)
- PhishTank: 1 req/sec
- URLhaus: 1 req/sec
"""

from utils.helpers import TokenBucketRateLimiter

# Pre-configured rate limiters per service
RATE_LIMITERS = {
    "virustotal": TokenBucketRateLimiter(rate=4 / 60, capacity=4),
    "shodan": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "nvd": TokenBucketRateLimiter(rate=50 / 30, capacity=10),
    "phishtank": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "urlhaus": TokenBucketRateLimiter(rate=1.0, capacity=1),
    "openphish": TokenBucketRateLimiter(rate=1.0, capacity=1),
}

__all__ = ["RATE_LIMITERS", "TokenBucketRateLimiter"]
