# Scanner Tools Evaluation — grey-hat-security-agent

**Document**: Phase 0 Research Deliverable  
**Date**: 2026-06-07  
**Status**: Complete  

---

## 1. Web Application Scanners Comparison

### 1.1 OWASP ZAP (Zed Attack Proxy)

| Attribute | Details |
|-----------|---------|
| **URL** | https://www.zaproxy.org |
| **License** | Apache 2.0 (free, open source) |
| **Language** | Java |
| **Latest Version** | 2.16 (as of 2026) |
| **API** | REST API (port 8080/8090 in daemon mode) |
| **Python Client** | python-owasp-zap-v2.4 (official) |

**Strengths**:
- Industry-standard OWASP project — most widely used free web scanner
- Comprehensive passive and active scan rules (4000+ rules)
- REST API allows full headless automation
- Daemon mode (zap.sh -daemon) for CI/CD and agent integration
- Supports authentication (form-based, script-based, API key)
- Produces HTML, XML, JSON, and Markdown reports
- Active community and frequent updates
- Spider and AJAX spider for comprehensive crawling
- Marketplace for add-ons (OpenAPI support, GraphQL, etc.)
- Can be run in Docker (zaproxy/zap-stable)

**Weaknesses**:
- Java dependency (requires JRE/JDK)
- Resource-intensive (memory-heavy, slow on large applications)
- Active scan can be aggressive and cause DoS if not tuned
- Daemon mode sometimes crashes and needs health-check + restart
- Learning curve for API scripting

**Integration Plan**:
`python
# Run ZAP in Docker daemon mode
# docker run -u zap -p 8080:8080 -p 8090:8090 zaproxy/zap-stable zap.sh -daemon -port 8090 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true

# Python integration
from zapv2 import ZAPv2
zap = ZAPv2(proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

# 1. Spider the target
zap.spider.scan(target_url)
while int(zap.spider.status()) < 100:
    time.sleep(1)

# 2. Passive scan (automatic during spidering)
while int(zap.pscan.records_to_scan()) > 0:
    time.sleep(1)

# 3. Active scan (requires auth token in our system)
zap.ascan.scan(target_url)
while int(zap.ascan.status()) < 100:
    time.sleep(2)

# 4. Get alerts
alerts = zap.core.alerts(baseurl=target_url)
`

---

### 1.2 Nikto

| Attribute | Details |
|-----------|---------|
| **URL** | https://github.com/sullo/nikto |
| **License** | GPL (free, open source) |
| **Language** | Perl |
| **Latest Version** | 2.5.0 |
| **API** | CLI only (no REST API) |
| **Python Integration** | Subprocess execution |

**Strengths**:
- Fast and lightweight web server scanner
- Checks for 6700+ potentially dangerous files/programs
- Detects outdated server versions and misconfigurations
- Good for quick initial assessment
- No heavy dependencies (just Perl)

**Weaknesses**:
- **No API** — must be invoked via subprocess, no programmatic control
- No JavaScript rendering — misses modern SPA vulnerabilities
- High false positive rate (many findings are informational)
- No authentication support — cannot scan authenticated areas
- No active exploitation capability
- Report format limited (CSV, HTML, XML, NBE)
- Perl dependency makes integration fragile

**Integration Plan**:
`python
# Only viable as subprocess
import subprocess
result = subprocess.run(
    ['nikto', '-h', target_url, '-Format', 'json', '-o', '/tmp/nikto_output.json'],
    capture_output=True, text=True, timeout=300
)
`

---

### 1.3 Nuclei (by ProjectDiscovery)

| Attribute | Details |
|-----------|---------|
| **URL** | https://github.com/projectdiscovery/nuclei |
| **License** | MIT (free, open source) |
| **Language** | Go |
| **Latest Version** | 3.3+ |
| **API** | CLI with JSON output |
| **Python Integration** | Subprocess + JSON parsing |

**Strengths**:
- Template-based scanning with 7000+ community templates
- Extremely fast (written in Go, uses goroutines)
- Templates organized by severity (critical, high, medium, low, info)
- CVE-specific templates — directly maps to CVE IDs
- Supports multiple protocols: HTTP, TCP, DNS, SSL, WebSocket, code
- Headless browser support (interactsh integration)
- Excellent for targeted vulnerability scanning (\"hunt for specific CVEs\")
- Active community and frequent template updates
- 
uclei-templates repo updated daily

**Weaknesses**:
- Go binary must be installed separately
- Template-based = finds only what templates exist for
- No built-in spidering — must provide URL list or use separate crawler
- Can be noisy (many requests)
- Requires template management (
uclei -ut to update templates)
- No built-in reporting beyond console/JSON/SARIF output

**Integration Plan**:
`python
# Run nuclei as subprocess with JSON output
import subprocess
result = subprocess.run(
    ['nuclei', '-u', target_url, '-json', '-o', '/tmp/nuclei_output.json',
     '-severity', 'critical,high,medium', '-rate-limit', '50'],
    capture_output=True, text=True, timeout=600
)
# Parse JSON results
import json
findings = json.loads(result_output)
`

---

### 1.4 Comparison Matrix

| Feature | OWASP ZAP | Nikto | Nuclei |
|---------|-----------|-------|--------|
| **License** | Apache 2.0 | GPL | MIT |
| **Scan Type** | Passive + Active | Server config | Template-based |
| **API Control** | Full REST API | None (CLI) | None (CLI + JSON) |
| **Python Integration** | Native (zapv2) | Subprocess only | Subprocess + JSON |
| **Authentication** | Full (form, script, API) | None | Basic, cookie |
| **Spider/Crawler** | Built-in (2 spiders) | None | None (needs URL list) |
| **CVE Mapping** | Via references | Via server checks | Direct template mapping |
| **Report Formats** | HTML, XML, JSON, MD | CSV, HTML, XML | JSON, SARIF, HTML |
| **Speed** | Slow (Java) | Medium | Fast (Go) |
| **False Positives** | Medium (tunable) | High | Low-Medium |
| **Resource Usage** | High (JVM) | Low | Low |
| **Community** | OWASP (large) | Small | Large (ProjectDiscovery) |
| **Docker Available** | Yes (official) | Yes (community) | Yes (official) |
| **JavaScript Rendering** | Via add-on | No | Via headless chrome |

---

### 1.5 Decision: Hybrid Approach

**Primary Scanner**: **OWASP ZAP** (daemon mode)
- Full API control for programmatic scanning
- Built-in spider for comprehensive crawling
- Authentication support for logged-in testing
- Industry standard — findings widely recognized
- Runs in Docker alongside agent

**Secondary Scanner**: **Nuclei** (subprocess)
- Fast CVE-specific template scanning
- Complements ZAP by targeting known CVEs directly
- Used after ZAP spider identifies URLs for targeted scanning
- JSON output easily parsed into Finding objects

**Not Selected**: **Nikto**
- No API control makes it unsuitable for agent integration
- High false positive rate
- Superseded by ZAP + Nuclei combination

---

## 2. Port Scanning: python-nmap vs. Subprocess

### 2.1 python-nmap Library

| Attribute | Details |
|-----------|---------|
| **Package** | python-nmap (PyPI) |
| **Version** | 0.7.1 |
| **URL** | https://github.com/kenn1/pyth0n-nmap |
| **Approach** | Python wrapper that calls nmap binary |

**Strengths**:
- Pythonic API for nmap scan results
- Parses XML output into structured Python objects
- Supports all nmap scan types (SYN, UDP, ACK, etc.)
- Async-compatible via 
map_async module
- No manual XML parsing needed

**Weaknesses**:
- Still requires nmap binary installed on system
- Limited error handling — crashes if nmap binary not found
- No streaming output — waits for full scan completion
- Maintained by community (not officially from nmap.org)

**Example Usage**:
`python
import nmap

nm = nmap.PortScanner()
nm.scan('203.0.113.0/24', '22-443', arguments='-sS -sV -O')

for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        for port in nm[host][proto].keys():
            service = nm[host][proto][port]
            print(f\"{host}:{port} {service['name']} {service['version']}\")
`

### 2.2 Direct Subprocess with XML Parsing

`python
import subprocess
import xml.etree.ElementTree as ET

result = subprocess.run(
    ['nmap', '-sS', '-sV', '-O', '-oX', '-', '203.0.113.0/24'],
    capture_output=True, text=True, timeout=300
)
root = ET.fromstring(result.stdout)
for host in root.findall('host'):
    for port in host.findall('ports/port'):
        service = port.find('service')
        print(f\"{host.find('address').get('addr')}:{port.get('portid')} {service.get('name')} {service.get('version')}\")
`

### 2.3 Comparison

| Feature | python-nmap | Subprocess + XML |
|---------|-------------|-----------------|
| **API** | Pythonic, object-oriented | Raw XML string parsing |
| **Dependencies** | python-nmap + nmap binary | nmap binary only |
| **Error Handling** | Built-in exceptions | Manual error parsing |
| **Async Support** | 
map_async module | syncio.create_subprocess_exec |
| **Output Parsing** | Automatic | Manual XML parsing |
| **Version Detection** | Built-in | Manual from XML |
| **Maintenance Risk** | Library abandonment | Direct XML spec is stable |
| **Code Clarity** | High | Medium |

### 2.4 Decision: python-nmap (with subprocess fallback)

**Primary**: Use python-nmap library for structured access to scan results
- Cleaner code, better error handling, automatic XML parsing
- 
map_async for non-blocking scans in FastAPI

**Fallback**: Direct subprocess execution if python-nmap has compatibility issues
- More fragile but guaranteed to work with any nmap version
- XML parsing is straightforward for our needs

**Both approaches require nmap binary installed** — this is unavoidable. Docker Compose will include nmap in the agent container.

---

## 3. SSL/TLS Checking: sslyze

### 3.1 sslyze Library

| Attribute | Details |
|-----------|---------|
| **Package** | sslyze (PyPI) |
| **Version** | 6.0+ |
| **URL** | https://github.com/nabla-c0d3/sslyze |
| **Approach** | Native Python SSL/TLS scanner |

**Integration Plan**:
`python
from sslyze import Scanner, ServerConnectivityInfo, ScanCommand

scanner = Scanner()
server_info = ServerConnectivityInfo(hostname=\"example.com\", port=443)
scanner.queue_scan(server_info, ScanCommand.SSL_2_0_SCAN)
scanner.queue_scan(server_info, ScanCommand.CERTIFICATE_INFO)
scanner.queue_scan(server_info, ScanCommand.ELLIPTIC_CURVES)

for result in scanner.get_results():
    # Process certificate info, cipher suites, protocols
    pass
`

**Checks Performed**:
- SSL 2.0/3.0 and TLS 1.0/1.1/1.2/1.3 support
- Certificate chain validation
- Certificate expiry
- Cipher suite strength
- HSTS header presence
- OCSP stapling support
- Known vulnerabilities (Heartbleed, POODLE, etc.)

---

## 4. Final Architecture: Scanner Integration

`
                    ┌─────────────────────────────┐
                    │    grey-hat-security-agent    │
                    │                               │
                    │  ┌─────────────────────────┐  │
                    │  │   Authorization Gate     │  │
                    │  │   (AuthToken verification)│  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │             ▼                  │
 Scan Command ───►  │  ┌─────────────────────────┐  │
                    │  │  Scanner Orchestrator    │  │
                    │  │  (coordinate scan phases)│  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │    ┌────────┼────────┐         │
                    │    │        │        │         │
                    │    ▼        ▼        ▼         │
                    │  ┌────┐ ┌────┐ ┌────────┐    │
                    │  │nmap│ │ZAP │ │nuclei  │    │
                    │  │    │ │    │ │        │    │
                    │  └──┬─┘ └──┬─┘ └───┬────┘    │
                    │     │      │       │          │
                    │     ▼      ▼       ▼          │
                    │  ┌─────────────────────────┐  │
                    │  │  Finding Aggregator      │  │
                    │  │  (normalize, dedup,     │  │
                    │  │   CVE match, score)      │  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │             ▼                  │
                    │  ┌─────────────────────────┐  │
                    │  │  Report Generator       │  │
                    │  │  (Claude → GPT-4o →      │  │
                    │  │   Mistral fallback)      │  │
                    │  └─────────────────────────┘  │
                    └─────────────────────────────┘
`

**Scan Phases (for authorized targets only)**:
1. **Reconnaissance**: nmap SYN scan + version detection
2. **SSL/TLS Assessment**: sslyze certificate and cipher suite analysis
3. **Web Crawling**: OWASP ZAP spider (passive)
4. **Web Scanning**: OWASP ZAP active scan (auth-gated)
5. **CVE Targeting**: Nuclei templates for discovered services
6. **Vulnerability Matching**: NVD CVE database lookup
7. **Report Generation**: LLM-assisted professional report
