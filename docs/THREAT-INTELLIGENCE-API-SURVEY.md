# Threat Intelligence API Survey — grey-hat-security-agent

**Document**: Phase 0 Research Deliverable  
**Date**: 2026-06-07  
**Status**: Complete  

---

## 1. Overview

This document surveys the threat intelligence APIs, data feeds, and external services that grey-hat-security-agent integrates with, including API capabilities, rate limits, authentication, data formats, and integration strategies.

---

## 2. VirusTotal

### 2.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://www.virustotal.com |
| **API Version** | v3 (REST) |
| **Authentication** | API key in x-apikey header |
| **Signup** | https://www.virustotal.com/gui/join-us |

### 2.2 Free Tier Limits
| Endpoint | Rate Limit | Daily Limit |
|----------|-----------|-------------|
| /api/v3/domains/{domain} | 4 requests/minute | 500 requests/day |
| /api/v3/ip_addresses/{ip} | 4 requests/minute | 500 requests/day |
| /api/v3/files/{hash} | 4 requests/minute | 500 requests/day |
| /api/v3/urls (scan) | 4 requests/minute | 500 requests/day |

### 2.3 Paid Tier (Premium)
| Plan | Rate Limit | Price |
|------|-----------|-------|
| Premium | 1000 req/min | Contact sales |
| Enterprise | Custom | Custom |

### 2.4 Key Endpoints for Agent
| Endpoint | Purpose | Response Fields |
|----------|---------|-----------------|
| GET /domains/{domain} | Domain reputation | last_analysis_stats, eputation, 	otal_votes, categories |
| GET /ip_addresses/{ip} | IP reputation | last_analysis_stats, sn, country, 
etwork |
| GET /domains/{domain}/subdomains | Subdomain enumeration | data[] with subdomain names |
| GET /domains/{domain}/relationships | Domain connections | Resolutions, downloaded files, communicating IPs |

### 2.5 Integration Strategy
- **Rate limiter**: Token bucket algorithm, 4 req/min, 500 req/day
- **Cache**: All VirusTotal responses cached in SQLite for 24 hours (TTL)
- **Priority queue**: Domain checks from PhishTank/OpenPhish feeds get priority
- **Fallback**: If VirusTotal rate limit hit, fall back to Shodan + cached data

---

## 3. Shodan

### 3.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://www.shodan.io |
| **API Version** | REST v1 |
| **Authentication** | API key in key query parameter |
| **Signup** | https://account.shodan.io/register |

### 3.2 Free Tier Limits
| Endpoint | Rate Limit | Monthly Limit |
|----------|-----------|---------------|
| /shodan/host/{ip} | 1 req/sec | 100 searches |
| /shodan/host/search | 1 req/sec | 100 searches |
| /shodan/org/{org} | 1 req/sec | 100 searches |

### 3.3 Paid Tier
| Plan | Rate Limit | Price |
|------|-----------|-------|
| Membership | 1 req/sec | /year (100 searches/day) |
| Freelancer | 1 req/sec | /year (5000 searches/day) |
| Enterprise | Custom | Custom |

### 3.4 Key Endpoints
| Endpoint | Purpose | Response Fields |
|----------|---------|-----------------|
| GET /shodan/host/{ip} | Host information | portnames, data (banners), ulns, os, org |
| GET /shodan/host/search | Search by query | matches[] with host data |
| GET /shodan/host/count | Count results | 	otal count |
| GET /dns/resolve | DNS resolution | {domain: ip} mapping |
| GET /org/{org} | Organization search | Hosts belonging to org |

### 3.5 Integration Strategy
- **Primary use**: IP enrichment — given a domain, resolve IP and get port/service info
- **Cache**: Shodan responses cached for 6 hours (TTL)
- **Rate limit**: 1 req/sec with exponential backoff on 429 responses
- **Complement**: Use Shodan for service banners when nmap not authorized for target

---

## 4. PhishTank

### 4.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://www.phishtank.com |
| **API Version** | Developer API |
| **Authentication** | API key via pp_key parameter |
| **Signup** | https://www.phishtank.com/developer_info.php |

### 4.2 API Endpoints
| Endpoint | Purpose | Format |
|----------|---------|--------|
| GET /phish_archive | All phishing URLs (bulk) | JSON |
| POST /phish_check/ | Check if URL is a phish | JSON |
| POST /phish_submit/ | Submit suspected phish | JSON (requires login) |

### 4.3 Rate Limits
- **No official rate limit** documented for developer API
- **Best practice**: 1 req/sec maximum, cache results locally
- **Bulk download**: Full archive available as JSON file (updated hourly)

### 4.4 Data Format
`json
{
  "phish_id": 123456,
  "url": "http://evil.example.com/login",
  "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=123456",
  "submission": {
    "time": "2026-06-01T12:00:00+00:00",
    "submitter": "anonymous"
  },
  "verification": true,
  "verification_time": "2026-06-01T12:30:00+00:00",
  "online": true,
  "target": "PayPal"
}
`

### 4.5 Integration Strategy
- **Ingestion**: Download full PhishTank archive daily (bulk JSON)
- **Deduplication**: Hash URLs with SHA-256; check against SQLite cache before processing
- **Enrichment**: New domains → VirusTotal API → Shodan API → composite risk score
- **Submission**: Agent can submit newly discovered phishing URLs via PhishTank API (requires operator login)

---

## 5. OpenPhish

### 5.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://www.openphish.com |
| **Authentication** | None (community feed) |
| **Signup** | Not required |

### 5.2 Feed URL
- **Community feed**: https://www.openphish.com/feed.txt (plain text, one URL per line)
- **Premium feed**: JSON with phishing URLs + brands + categories (requires license)

### 5.3 Data Format (Community)
`
http://evil.example1.com/login
http://malicious-site.com/bank
http://phish-site.net/secure
`

### 5.4 Data Format (Premium)
`json
{
  "url": "http://evil.example.com/login",
  "brand": "PayPal",
  "category": "Financial",
  "threat_type": "Phishing",
  "first_seen": "2026-06-01",
  "last_seen": "2026-06-07"
}
`

### 5.5 Integration Strategy
- **Ingestion**: Fetch community feed every 6 hours
- **Processing**: Parse each URL, extract domain, deduplicate against SQLite cache
- **Enrichment**: Novel domains → VirusTotal + Shodan for risk scoring
- **No rate limit**: Community feed has no API rate limit, but respect server load with 6-hour intervals

---

## 6. URLhaus

### 6.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://urlhaus.abuse.ch |
| **API Version** | REST API |
| **Authentication** | None (public) |
| **Signup** | Not required |

### 6.2 API Endpoints
| Endpoint | Purpose | Method |
|----------|---------|--------|
| /api/v1/urls/ | Recent URLs (paginated) | POST with {"limit": 100} |
| /api/v1/urls/{url_id} | Specific URL details | GET |
| /api/v1/urls/host/{hostname} | URLs for a hostname | POST |
| /api/v1/urls/tag/{tag} | URLs by tag | POST |
| /api/v1/servers/ | Recent servers | POST |

### 6.3 Rate Limits
- **No official rate limit** documented
- **Best practice**: 1 req/sec maximum

### 6.4 Data Format
`json
{
  "url": "http://evil.example.com/malware.exe",
  "url_status": "online",
  "date_added": "2026-06-01T12:00:00+00:00",
  "threat": "malware_download",
  "host": "evil.example.com",
  "tags": ["exe", "malware"],
  "reporter": "anonymous",
  "takedown_time_seconds": 3600
}
`

### 6.5 Integration Strategy
- **Ingestion**: Poll /api/v1/urls/ every 4 hours for new URLs
- **Domain query**: Given a domain, query /api/v1/urls/host/{domain} for associated malware URLs
- **Tag filtering**: Filter by tags (malware_download, c2, ansomware) for focused analysis

---

## 7. NVD (National Vulnerability Database) — NIST

### 7.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://nvd.nist.gov |
| **API Version** | 2.0 (REST) |
| **Authentication** | API key in header (optional for higher rate limits) |
| **Signup** | https://nvd.nist.gov/developers/request-an-api-key |

### 7.2 API Endpoints
| Endpoint | Purpose | Parameters |
|----------|---------|------------|
| GET /rest/json/cves/2.0 | Search CVEs | cveId, keywordSearch, pubStartDate, modStartDate |
| GET /rest/json/cves/2.0?cveId={id} | Specific CVE | Single CVE ID |
| GET /rest/json/cpes/2.0 | Search CPEs | cpeMatchString |
| GET /rest/json/source/2.0 | Source info | — |

### 7.3 Rate Limits
| Tier | Rate Limit | Notes |
|------|-----------|-------|
| No API key | 5 requests per 30 seconds | Rolling window |
| With API key | 50 requests per 30 seconds | API key in piKey header |

### 7.4 Data Format (CVE 2.0)
`json
{
  "cve": {
    "id": "CVE-2024-1234",
    "sourceIdentifier": "cve@mitre.org",
    "published": "2024-01-15T12:00:00.000",
    "lastModified": "2024-06-01T08:00:00.000",
    "descriptions": [{"lang": "en", "value": "Vulnerability description..."}],
    "metrics": {
      "cvssMetricV31": [{
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore": 9.8,
          "baseSeverity": "CRITICAL"
        }
      }]
    },
    "weaknesses": [{"description": [{"value": "CWE-89"}]}],
    "references": [{"url": "https://..."}]
  }
}
`

### 7.5 Integration Strategy
- **Initial load**: Download all NVD CVE 2.0 annual feeds for years 2020–2026 (~200k CVEs)
- **Delta updates**: Use modStartDate and modEndDate parameters to fetch only modified CVEs since last run
- **Storage**: All CVEs stored in SQLite cve table with full-text search on descriptions
- **Rate limit**: With API key: 50 req/30 sec; without: 5 req/30 sec. Use sliding window rate limiter.
- **CVSS extraction**: Parse cvssMetricV31 for base, temporal, and environmental scores
- **CPE matching**: Store CPE strings for service/version matching in scan command

---

## 8. MITRE ATT&CK

### 8.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://attack.mitre.org |
| **Format** | STIX 2.1 JSON |
| **Download** | https://github.com/mitre/cti (enterprise-attack.json) |
| **Authentication** | None required |

### 8.2 Data Structure
- **Tactics**: 14 top-level categories (Reconnaissance → Impact)
- **Techniques**: 200+ specific attack methods
- **Sub-techniques**: Granular variants of techniques
- **Groups**: Named threat actor groups (APT28, Lazarus Group, etc.)
- **Software**: Malware and legitimate tools used in attacks
- **Mitigations**: Defensive measures per technique

### 8.3 Key STIX Object Types
| Type | Description | ID Pattern |
|------|-------------|-----------|
| ttack-pattern | Technique or sub-technique | ttack-pattern--{uuid} |
| intrusion-set | Threat actor group | intrusion-set--{uuid} |
| malware | Malicious software | malware--{uuid} |
| 	ool | Legitimate tool used offensively | 	ool--{uuid} |
| course-of-action | Mitigation | course-of-action--{uuid} |
| elationship | Links between objects | elationship--{uuid} |

### 8.4 Integration Strategy
- **Download**: Fetch enterprise-attack.json from MITRE CTI GitHub repo monthly
- **Parse**: Extract all techniques with tactic mapping, software associations, and mitigations
- **Storage**: Store in SQLite mitre_techniques table with FTS on descriptions
- **Mapping**: Given a CVE or finding type, map to relevant ATT&CK technique(s)
- **Report inclusion**: Include ATT&CK Tactic → Technique mapping in generated reports

---

## 9. Exploit-DB

### 9.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://www.exploit-db.com |
| **Search API** | https://www.exploit-db.com/search (web interface) |
| **CSV Archive** | https://www.exploit-db.com/exploits.csv (updated daily) |
| **Authentication** | None required |

### 9.2 Data Format (CSV Archive)
`
id,file,description,date,author,type,platform,port
12345,12345.py,"Apache 2.4 - Path Traversal",2024-01-15,researcher,webapps,php,80
`

### 9.3 Integration Strategy
- **Initial load**: Download exploits.csv and store in SQLite exploitdb table
- **Delta updates**: Weekly re-download and diff against local copy
- **Matching**: Given a service/version string, search Exploit-DB for matching exploits
- **PoC retrieval**: Download individual exploit files for Docker sandbox execution (auth token required)

---

## 10. Google Safe Browsing

### 10.1 Overview
| Attribute | Value |
|-----------|-------|
| **URL** | https://developers.google.com/safe-browsing |
| **API Version** | v4 (REST) |
| **Authentication** | API key |
| **Signup** | https://console.cloud.google.com (enable Safe Browsing API) |

### 10.2 Key Endpoints
| Endpoint | Purpose |
|----------|---------|
| POST /threatMatches:find | Check if URL is in Safe Browsing lists |
| POST /threatListUpdates:fetch | Get incremental updates to threat lists |
| POST /fullHashes:find | Get full hashes for prefix matches |

### 10.3 Rate Limits
- **Free**: 10,000 queries/day
- **No per-minute rate limit** for Lookup API

### 10.4 Integration Strategy
- **Submission**: Agent submits confirmed phishing/malware URLs to Safe Browsing Submission API
- **Lookup**: Check URLs against Safe Browsing before reporting (avoid false positives)
- **Update**: Subscribe to threat list updates for local caching

---

## 11. API Integration Summary Table

| API | Purpose | Free Tier | Rate Limit | Data Format | Priority |
|-----|---------|-----------|------------|-------------|----------|
| **VirusTotal** | Domain/IP reputation | 500 req/day | 4 req/min | JSON | High |
| **Shodan** | IP service enumeration | 100 searches | 1 req/sec | JSON | Medium |
| **PhishTank** | Phishing URL database | Unlimited | 1 req/sec | JSON | High |
| **OpenPhish** | Active phishing feed | Unlimited | N/A | Plain text | High |
| **URLhaus** | Malware URL database | Unlimited | 1 req/sec | JSON | Medium |
| **NVD** | CVE database | Free (key recommended) | 5-50 req/30sec | JSON | Critical |
| **MITRE ATT&CK** | TTP taxonomy | Free | N/A | STIX 2.1 | Critical |
| **Exploit-DB** | Public exploits | Free | N/A | CSV | Medium |
| **Google Safe Browsing** | URL safety check | 10,000/day | No limit | JSON | Medium |

---

## 12. Rate Limiting Architecture

`python
# core/intel/rate_limiter.py

class TokenBucketRateLimiter:
    \"\"\"Generic token bucket rate limiter for API calls.\"\"\"
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate          # tokens per second
        self.capacity = capacity   # max burst size
        self.tokens = capacity
        self.last_refill = time.monotonic()
    
    async def acquire(self) -> bool:
        # Refill tokens based on elapsed time
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False
    
    async def wait_and_acquire(self) -> None:
        while not await self.acquire():
            await asyncio.sleep(1.0 / self.rate)

# Configuration
RATE_LIMITERS = {
    "virustotal": TokenBucketRateLimiter(rate=4/60, capacity=4),   # 4 req/min
    "shodan": TokenBucketRateLimiter(rate=1, capacity=1),           # 1 req/sec
    "nvd": TokenBucketRateLimiter(rate=50/30, capacity=10),          # 50 req/30sec with key
    "phishtank": TokenBucketRateLimiter(rate=1, capacity=1),        # 1 req/sec
    "urlhaus": TokenBucketRateLimiter(rate=1, capacity=1),          # 1 req/sec
}
`

---

## 13. Composite Risk Score Formula

`python
# core/intel/risk_score.py

def calculate_composite_risk_score(
    vt_detections: float,       # VirusTotal detection ratio (0.0 - 1.0)
    phish_tank_hits: int,       # Number of PhishTank entries
    open_phish_hits: int,       # Number of OpenPhish entries
    urlhaus_hits: int,          # Number of URLhaus entries
    domain_age_days: int,       # Days since domain registration
    secroberta_score: float,    # SecRoBERTa phishing probability (0.0 - 1.0)
    whois_anomalies: float,     # WHOIS anomaly score (0.0 - 1.0)
) -> float:
    \"\"\"
    Calculate composite risk score (0-100) for a domain.
    
    Weight distribution:
    - VirusTotal detections: 30%
    - Feed hits (PhishTank + OpenPhish + URLhaus): 20%
    - SecRoBERTa NLP classification: 25%
    - Domain age: 15%
    - WHOIS anomalies: 10%
    \"\"\"
    
    # Normalize feed hits (0-1 scale, diminishing returns)
    feed_score = 1 - (1 / (1 + phish_tank_hits + open_phish_hits + urlhaus_hits))
    
    # Domain age factor (younger = riskier)
    age_factor = 1 - min(domain_age_days / 365, 1.0)  # 1 year = max age factor
    
    composite = (
        0.30 * vt_detections +
        0.20 * feed_score +
        0.25 * secroberta_score +
        0.15 * age_factor +
        0.10 * whois_anomalies
    )
    
    return round(composite * 100, 1)  # Scale to 0-100
`

Risk score interpretation:
| Score | Level | Action |
|-------|-------|--------|
| 0–20 | Low | Monitor only |
| 21–40 | Moderate | Investigate further |
| 41–60 | High | Flag for review |
| 61–80 | Critical | Report to authority |
| 81–100 | Imminent | Immediate report to CERT/Safe Browsing |
