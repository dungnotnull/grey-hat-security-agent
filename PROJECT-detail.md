# PROJECT-detail.md — grey-hat-security-agent

## Executive Summary
grey-hat-security-agent is an authorized cybersecurity research and red-team intelligence assistant that combines continuous self-learning (via security paper ingestion and CVE feed monitoring) with structured, permission-gated vulnerability assessment workflows. The agent operates in two distinct modes: (1) **Threat Intelligence Mode** — passively aggregating, scoring, and reporting known scam/phishing/malicious infrastructure to appropriate authorities; and (2) **Authorized Assessment Mode** — performing structured penetration testing and vulnerability scanning exclusively against systems with explicit written authorization. All findings are compiled into professional, CVSS v3.1-scored vulnerability disclosure reports with MITRE ATT&CK technique mappings.

**Ethics Boundary**: The original project idea included "destroying" scam websites as a goal. This capability is explicitly excluded — unauthorized offensive actions against any system, even malicious ones, violate computer crime laws globally (CFAA, Computer Misuse Act, Vietnamese Cybersecurity Law 2018). The agent instead performs authorized security research and submits intelligence to legitimate authorities.

---

## Problem Statement

### The Defender's Disadvantage
- The cybersecurity industry faces a **3.5 million global workforce shortage** (ISC² 2023 Cybersecurity Workforce Study).
- Phishing attacks increased **47% YoY** in 2023, with 1.35 million unique phishing sites detected monthly (APWG Q4 2023 Report).
- Average time-to-report a vulnerability after discovery is **30+ days** for human researchers (HackerOne 2023 Annual Report).
- Bug bounty programs paid **$300M+** in 2023, yet thousands of valid vulnerabilities remain unreported due to friction in the workflow.
- Security professionals spend **60%+ of working time** on manual reconnaissance and report writing — tasks highly amenable to AI automation.
- Scam/phishing infrastructure spins up new domains in under 5 minutes; manual threat intelligence teams cannot keep pace.

### The Opportunity
An AI agent that continuously ingests security research, automates reconnaissance and vulnerability correlation, and generates publication-ready reports can compress the 30-day researcher workflow to hours — while maintaining strict authorization controls that protect operators from legal liability.

---

## Target Users & Use Cases

| User Type | Primary Use Case |
|-----------|-----------------|
| Bug bounty hunters | Automate recon + CVE matching within program scope; generate structured reports |
| Penetration testers | Cross-reference findings with CVE/ATT&CK databases; draft professional reports |
| Security researchers | Track emerging vulnerabilities; ingest new papers weekly |
| SOC analysts | Enrich threat intel feeds with domain scoring and categorization |
| CERT/CSIRT teams | Bulk analysis and authority submission of reported suspicious domains |
| Independent developers | Audit their own infrastructure against known vulnerabilities |
| Vietnamese enterprises | VN-specific scam ecosystem intelligence (VNCERT submission pipeline) |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                      grey-hat-security-agent                         │
│                                                                      │
│  ┌───────────────┐   ┌────────────────────┐   ┌──────────────────┐  │
│  │  CLI (Typer)  │   │  REST API (FastAPI) │   │  Auth Gate       │  │
│  │  intel/scan/  │   │  /api/v1/...        │   │  (MANDATORY)     │  │
│  │  report/auth  │   └────────────────────┘   │  JWT + Signature │  │
│  └──────┬────────┘                            └────────┬─────────┘  │
│         └────────────────────────────────────────────┘             │
│                              │                                       │
│         ┌────────────────────┼────────────────────┐                 │
│         ▼                    │                    ▼                  │
│  ┌─────────────────┐         │         ┌──────────────────────────┐ │
│  │ THREAT INTEL    │         │         │ AUTHORIZED ASSESSMENT    │ │
│  │ (passive only)  │         │         │ ENGINE (auth token req.) │ │
│  │                 │         │         │                          │ │
│  │ PhishTank feed  │         │         │ nmap port/svc scan       │ │
│  │ OpenPhish feed  │         │         │ OWASP ZAP web scanner    │ │
│  │ URLhaus feed    │         │         │ SSL/TLS checker          │ │
│  │ VirusTotal API  │         │         │ CVE Matcher (NVD API)    │ │
│  │ MITRE ATT&CK   │         │         │ Docker PoC Sandbox       │ │
│  │ Shodan API      │         │         │ Directory/Param fuzzer   │ │
│  └────────┬────────┘         │         └─────────────┬────────────┘ │
│           │                  │                       │               │
│           └──────────────────┼───────────────────────┘               │
│                              ▼                                        │
│                 ┌────────────────────────┐                           │
│                 │  ANALYSIS & SCORING    │                           │
│                 │                        │                           │
│                 │  CVSS v3.1 Calculator  │                           │
│                 │  SecRoBERTa NLP        │                           │
│                 │  CodeBERT code scan    │                           │
│                 │  MITRE ATT&CK mapper   │                           │
│                 │  Risk aggregator       │                           │
│                 └────────────┬───────────┘                          │
│                              │                                        │
│                              ▼                                        │
│                 ┌────────────────────────┐                           │
│                 │  LLM REPORT ENGINE     │                           │
│                 │  Claude (primary)      │                           │
│                 │  GPT-4o (fallback)     │                           │
│                 │  Mistral-7B (offline)  │                           │
│                 └────────────┬───────────┘                          │
│                              │                                        │
│                              ▼                                        │
│                 ┌────────────────────────┐                           │
│                 │  OUTPUT LAYER          │                           │
│                 │  PDF/Markdown reports  │                           │
│                 │  Authority submissions │                           │
│                 │  Dashboard (FastAPI)   │                           │
│                 │  STIX/TAXII export     │                           │
│                 └────────────────────────┘                          │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  SELF-LEARNING LOOP (crawl4ai, weekly)                        │   │
│  │  ArXiv cs.CR  |  NVD delta feed  |  Exploit-DB  |  ATT&CK   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Version | Source |
|-----------|-----------|---------|--------|
| Language | Python | 3.11 | python.org |
| API Framework | FastAPI | 0.111 | fastapi.tiangolo.com |
| CLI | Typer | 0.12 | typer.tiangolo.com |
| Web Crawler | crawl4ai | 0.3+ | github.com/unclecode/crawl4ai |
| Port Scanner | python-nmap | 0.7.1 | python-nmap.readthedocs.io |
| Web App Scanner | OWASP ZAP API (zaproxy) | 0.3+ | github.com/zaproxy/zaproxy |
| Database | SQLite + SQLAlchemy | 2.0.30 | sqlalchemy.org |
| Encryption | cryptography (AES-256-GCM) | 42.0.5 | pypi.org/project/cryptography |
| Local LLM | Ollama | latest | ollama.ai |
| LLM SDK | anthropic | 0.27+ | pypi.org/project/anthropic |
| ML Framework | PyTorch | 2.3 | pytorch.org |
| Transformers | HuggingFace transformers | 4.41 | huggingface.co |
| Docker SDK | docker | 7.0 | pypi.org/project/docker |
| PDF Reports | ReportLab | 4.2 | reportlab.com |
| HTTP Client | aiohttp + httpx | 3.9.5 / 0.27 | — |
| Visualization | Rich (CLI), Jinja2 (HTML) | — | — |
| Validation | pydantic | 2.7 | pydantic.dev |
| Env Config | python-dotenv | 1.0.1 | — |

---

## ML/DL Models

### SecRoBERTa — Security Domain NLP
- **HuggingFace ID**: `jackaduma/SecRoBERTa`
- **Purpose**: CVE text classification, severity keyword extraction, phishing/malware content detection
- **Architecture**: RoBERTa pre-trained on cybersecurity-domain text corpora
- **Fine-tuning plan**: Fine-tune on NVD CVE descriptions + MITRE ATT&CK technique descriptions with severity labels (Critical/High/Medium/Low/Info)
- **Training data**: NVD JSON feed (200k+ CVEs), PhishTank verified phishing pages, MITRE ATT&CK technique database
- **Inference**: Local, CPU-capable (quantized INT8 for edge deployment)

### CodeBERT — Vulnerable Code Pattern Detection
- **HuggingFace ID**: `microsoft/codebert-base`
- **Purpose**: Detect insecure code patterns in source snippets (SQL injection, path traversal, buffer overflow, hardcoded secrets, SSRF)
- **Architecture**: Bimodal transformer trained on code + natural language
- **Fine-tuning plan**: Fine-tune on CWE-labeled samples from NIST SARD and CodeQL security query outputs
- **Training data**: NIST SARD (Software Assurance Reference Dataset), CodeQL GitHub Actions security results, Snyk vulnerability database

### Mistral-7B-Instruct — Local Report Drafting
- **HuggingFace ID**: `mistralai/Mistral-7B-Instruct-v0.3`
- **Purpose**: Offline fallback for report drafting, remediation suggestions, CVE analysis
- **Deployment**: Ollama local server (4-bit GGUF quantized)
- **Fine-tuning plan**: Optional LoRA fine-tune on HackerOne public vulnerability disclosures for report style alignment
- **Memory requirement**: ~4GB VRAM (GGUF Q4) or 8GB RAM (CPU inference)

---

## External LLM API Integration

Pluggable backend with automatic fallback chain:

```python
# config.py
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "claude")  # claude | openai | ollama

FALLBACK_CHAIN = [
    {
        "provider": "claude",
        "model": "claude-opus-4-8",
        "key_env": "CLAUDE_API_KEY",
        "max_tokens": 4096
    },
    {
        "provider": "openai",
        "model": "gpt-4o",
        "key_env": "OPENAI_API_KEY",
        "max_tokens": 4096
    },
    {
        "provider": "ollama",
        "model": "mistral:7b-instruct",
        "base_url_env": "OLLAMA_BASE_URL",
        "max_tokens": 2048
    },
]
```

All LLM calls go through `async_llm_call(prompt, context)` which:
1. Tries providers in order until one succeeds
2. Caches responses in SQLite (keyed by SHA-256 of prompt) to avoid redundant API calls
3. Never logs raw API keys; redacts them from all output

---

## Feature Specification

### MVP Features
- [ ] Authorization token system (JSON: `{target, scope[], expiry_unix, approver_name, signature}`)
- [ ] Threat intelligence aggregation (PhishTank, OpenPhish, URLhaus, VirusTotal read-only)
- [ ] Domain reputation scoring (composite: VT detections + PhishTank hits + domain age + WHOIS anomalies)
- [ ] CVSS v3.1 standalone Python calculator with vector string parser
- [ ] NVD CVE feed ingestion and local SQLite mirror (delta updates)
- [ ] Port/service enumeration via nmap wrapper (authorized targets only, requires auth token)
- [ ] SSL/TLS configuration checker (expired certs, weak ciphers, missing HSTS, OCSP stapling)
- [ ] CVE matcher (correlate detected service+version strings against local NVD mirror)
- [ ] LLM report generator (markdown + PDF output via ReportLab)
- [ ] CLI: `intel <domain>`, `scan <target>`, `report <scan-id>`, `authorize <target>`, `update`
- [ ] AES-256-GCM encrypted SQLite storage for all findings and authorization tokens
- [ ] crawl4ai self-update pipeline (weekly ArXiv cs.CR + NVD delta + Exploit-DB)
- [ ] Audit log: every action recorded with timestamp, target, auth token hash

### Advanced Features
- [ ] OWASP ZAP full web application security testing (passive + active scan modes)
- [ ] Docker PoC sandbox: execute CVE proof-of-concept code in `--network none` container
- [ ] SecRoBERTa fine-tuned classifier for CVE severity and phishing detection
- [ ] CodeBERT source code vulnerability scanner for GitHub repositories
- [ ] MITRE ATT&CK TTP mapper (findings → technique IDs with tactic context)
- [ ] Automated responsible disclosure email generator with PDF attachment
- [ ] Bug bounty scope parser: HackerOne/Bugcrowd program JSON → authorization tokens
- [ ] Threat actor infrastructure clustering (shared IP/ASN/registrar graph analysis)
- [ ] Authority submission pipeline (Google Safe Browsing, CERT/CC, PhishTank, VNCERT)
- [ ] STIX/TAXII 2.1 export for threat intelligence sharing with partner organizations
- [ ] FastAPI dashboard: finding visualization, trend charts, CVE timeline
- [ ] Remediation re-test: re-scan after client patches → auto-generate "verified closed" addendum

---

## Full E2E Data Flow

### Mode 1: Threat Intelligence (Passive)
1. crawl4ai scheduler triggers daily pull from PhishTank JSON feed, OpenPhish CSV, URLhaus API
2. New domains deduplicated against SQLite cache; novel entries queued for enrichment
3. VirusTotal API called per domain: detection ratio, categories, WHOIS, hosting ASN
4. Shodan API called per IP: open ports, banners, known vulnerabilities
5. SecRoBERTa classifies domain/page content → {phishing, malware, scam, benign} + confidence
6. Composite risk score (0–100) computed: 40% VT detections + 30% SecRoBERTa score + 20% domain age + 10% WHOIS anomalies
7. Domains scoring > 80 flagged; LLM generates threat landscape summary report
8. High-risk domains submitted to Google Safe Browsing Submission API and VNCERT (Vietnamese targets)
9. All data stored in encrypted SQLite; never auto-forwarded to external parties without user approval

### Mode 2: Authorized Assessment (Active)
1. User runs `authorize` command: inputs target domain/IP, scope, expiry date, approver name
2. Agent generates JSON authorization token; user signs with their private key (Ed25519)
3. Signed token stored in encrypted SQLite; validity checked before every active command
4. `scan` command: nmap SYN scan + version detection → structured service inventory
5. SSL/TLS checker runs: certificate chain, expiry, cipher suites, HSTS, certificate transparency
6. CVE Matcher queries local NVD mirror: for each detected service/version, returns matching CVEs with CVSS scores
7. OWASP ZAP (if enabled): passive crawl → active scan on in-scope URLs (auth token scope enforced)
8. All raw findings aggregated into `Finding` objects: `{title, cvss_vector, severity, affected_component, evidence, cve_ids}`
9. CVSS v3.1 scores calculated for each finding; MITRE ATT&CK techniques mapped
10. LLM report engine drafts professional pentest report: executive summary + technical details + reproduction steps + remediation recommendations
11. ReportLab renders PDF; user reviews full report before any sharing
12. Optional: agent drafts responsible disclosure email to target's security contact for user review and manual send

---

## Privacy & Security

| Concern | Mitigation |
|---------|-----------|
| Findings at rest | AES-256-GCM application-layer encryption on all SQLite tables |
| API key exposure | Keys in `.env` only; never stored in DB or logged |
| Active scanning without permission | Authorization token with signature required; checked cryptographically |
| PoC code execution | Docker container with `--network none`, no volume mounts, auto-destroyed after run |
| Audit trail | Immutable append-only log in SQLite: action, target, auth_token_hash, timestamp, user_id |
| Rate limiting | Built-in rate limiting on VirusTotal (4 req/min free tier), Shodan, NVD APIs |
| Report distribution | Reports never auto-sent; user must explicitly trigger email send |
| Zero unilateral attacks | No code path exists for sending attack traffic without explicit user command + valid auth token |

---

## Key Python Dependencies

```
# requirements.txt
anthropic>=0.27.0
openai>=1.30.0
crawl4ai>=0.3.0
python-nmap>=0.7.1
zaproxy>=0.3.0
sqlalchemy>=2.0.30
cryptography>=42.0.5
docker>=7.0.0
transformers>=4.41.0
torch>=2.3.0
reportlab>=4.2.0
fastapi>=0.111.0
uvicorn>=0.30.0
typer>=0.12.0
aiohttp>=3.9.5
httpx>=0.27.0
pydantic>=2.7.0
python-dotenv>=1.0.1
rich>=13.7.0
stix2>=3.0.1
taxii2-client>=2.3.0
```

---

## Improvement Suggestions

1. **CVE-to-PoC mapping**: Auto-link CVEs to public PoC repositories (Exploit-DB, GitHub advisories) for faster verification — sandbox execution only, human approval required.
2. **Threat actor infrastructure clustering**: Group scam domains by shared IP/ASN/registrar fingerprints to identify coordinated campaigns, not just individual bad domains.
3. **Natural language scope parser**: Accept HackerOne/Bugcrowd program pages as URL input — LLM extracts in-scope domains and auto-creates authorization tokens, reducing setup friction.
4. **AI-assisted triage**: Use Claude to prioritize findings by exploitability × business impact for the specific target context (e.g., payment processor vs. personal blog get different CVSS weights).
5. **Continuous monitoring mode**: Poll authorized targets' public endpoints on a schedule; alert on delta changes (new open ports, changed TLS config, new CVEs for detected versions).
6. **Federated threat sharing**: Export threat intelligence in STIX 2.1/TAXII format for sharing with CERTs and ISACs without manual data entry.
7. **Remediation verification loop**: After client patches, re-scan and auto-generate "verified closed" addendum to the original report — reduces follow-up effort by 80%.
8. **Vietnamese scam ecosystem focus**: Dedicated mode for Vietnamese-language phishing pages using a VietnameseNLP classifier; direct submission pipeline to VNCERT and BKAV threat intelligence.
9. **Integration with Folder 7 (secure-orchestration-mesh)**: Use the mesh's Zero-Trust communication layer for secure multi-agent coordination during large-scale red-team engagements.
10. **Hallucination guard for LLM reports**: Post-process all LLM-generated report content by verifying every cited CVE ID and CVSS score against the local NVD mirror before including in the final PDF.
