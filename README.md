<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Tests-87%20passing-brightgreen?style=for-the-badge" alt="87 Tests">
  <img src="https://img.shields.io/badge/Security-Authorized%20Only-red?style=for-the-badge" alt="Authorized Only">
</p>

<h1 align="center">grey-hat-security-agent</h1>

<p align="center">
  <strong>Authorized Cybersecurity Research & Red-Team Intelligence Agent</strong>
</p>

<p align="center">
  A permission-gated security assessment platform that combines continuous self-learning<br>
  with structured vulnerability assessment, CVSS v3.1 scoring, and MITRE ATT&CK mapping.<br>
  Every active scan requires a cryptographically-signed authorization token.
</p>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Authorization System](#authorization-system)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Deployment](#deployment)
- [Security Policy](#security-policy)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**Two Operating Modes:**

1. **Threat Intelligence Mode** - Passively aggregate, score, and report malicious infrastructure (PhishTank, OpenPhish, URLhaus, VirusTotal, Shodan)
2. **Authorized Assessment Mode** - Perform structured penetration testing exclusively against systems with explicit written authorization (nmap, ZAP, nuclei, sslyze)

> **Ethics Boundary**: No code path exists for sending attack traffic without explicit user command + valid auth token. Scam/phishing domain discovery is strictly read-only threat intelligence.

---

## Architecture

`
CLI (Typer) ---+
               +--- Auth Gate (MANDATORY Ed25519 token verification)
REST API ------+
                       |
           +-----------+-----------+
           |                       |
           v                       v
   THREAT INTEL              AUTHORIZED ASSESSMENT
   (passive only)            (auth token required)
           |                       |
           v                       v
   ANALYSIS & SCORING ----- LLM REPORT ENGINE
   (CVSS, SecRoBERTa,      (Claude -> GPT-4o -> Mistral)
    CodeBERT, ATT&CK)
           |                       |
           +-----------+-----------+
                       |
                       v
               OUTPUT LAYER
   (PDF/MD/HTML reports, authority submissions, STIX/TAXII)
                       |
                       v
              SELF-LEARNING LOOP
   (ArXiv, NVD, Exploit-DB, MITRE, HuggingFace)
`

---

## Features

### Core Security
- **Ed25519 Authorization Gate** - Every scan requires a signed token; tampered tokens are rejected
- **CVSS v3.1 Calculator** - Spec-correct implementation with Roundup function, passes all NIST test vectors
- **MITRE ATT&CK Mapping** - CWE-to-TTP and service-to-TTP mappings with fallback data
- **AES-256-GCM Encryption** - All sensitive database fields encrypted at application layer

### Threat Intelligence
- **6 Feed Integrations** - PhishTank, OpenPhish, URLhaus, VirusTotal, Shodan, NVD
- **Composite Risk Scoring** - 5-factor weighted formula (VT 30%, feeds 20%, NLP 25%, age 15%, WHOIS 10%)
- **SecRoBERTa NLP** - Security-domain text classification with heuristic fallback
- **Auto-update Pipeline** - Weekly ArXiv, NVD delta, Exploit-DB, MITRE ATT&CK ingestion

### Scanning & Analysis
- **4 Scanner Integrations** - nmap, OWASP ZAP, nuclei, sslyze
- **CodeBERT Scanner** - Detects SQL injection, path traversal, XSS, SSRF, hardcoded creds, and more
- **CVE Matcher** - Local NVD mirror for offline CVE lookups
- **Docker Sandbox** - Isolated PoC execution with --network none

### Reporting
- **3 Output Formats** - Markdown, PDF (ReportLab), HTML
- **LLM Fallback Chain** - Claude -> GPT-4o -> Mistral-7B with 7-day SQLite cache
- **CVE Hallucination Guard** - Strips LLM-generated CVE IDs not found in local NVD mirror
- **Responsible Disclosure Email** - Pre-formatted disclosure email templates

### DevOps
- **FastAPI REST API** - 19 endpoints with rate limiting and CORS
- **Typer CLI** - 9 commands with Rich output
- **Docker Compose** - Agent + ZAP + Ollama
- **GitHub Actions CI** - Lint, type check, test
- **87 tests passing** across auth, CVSS, crypto, scanners, ML, reporting

---

## Quick Start

### Prerequisites

- Python 3.11+
- nmap (for port scanning)
- Docker (optional, for ZAP and sandbox)

### Installation

`powershell
# 1. Clone the repository
git clone https://github.com/dungnotnull/grey-hat-security-agent.git
cd grey-hat-security-agent

# 2. Run setup script
.\setup.ps1

# 3. Copy and configure .env
Copy-Item .env.example .env
# Edit .env and add your API keys

# 4. (Optional) Install Ollama for offline LLM
# Download from https://ollama.ai/download
# Then: ollama pull mistral:7b-instruct

# 5. Run tests
.\venv\Scripts\python.exe -m pytest tests\ -v
`

### Linux/macOS

`ash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env
python -m pytest tests/ -v
`

---

## CLI Reference

`ash
# Threat Intelligence
python main.py intel score <domain>          # Score domain risk (0-100)
python main.py intel check <domain>          # Check all threat feeds

# Authorized Assessment
python main.py authorize keygen               # Generate Ed25519 keypair
python main.py authorize create --target example.com --scope "port_scan,ssl_tls_check"
python main.py authorize sign --token-file token.json --key-file <id>.priv
python main.py authorize verify --token-file signed-token.json
python main.py scan run --target example.com --token-file signed-token.json
python main.py scan dry-run --target example.com

# Reports
python main.py report generate --scan-id <id> --format pdf
python main.py report email-draft --scan-id <id> --org "Example Corp"

# Knowledge Base
python main.py update --source all           # Update from security feeds

# Database
python main.py db-init                        # Initialize database schema

# Sandbox
python main.py sandbox                       # Check Docker availability
`

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/token | Create authorization token |
| POST | /api/v1/auth/sign | Sign token with Ed25519 key |
| POST | /api/v1/auth/verify | Verify token signature |
| POST | /api/v1/intel/score | Score domain risk |
| POST | /api/v1/intel/check | Check domain across all feeds |
| POST | /api/v1/scan | Start authorized scan |
| GET | /api/v1/scan/{id} | Get scan results |
| POST | /api/v1/report/generate | Generate report |
| POST | /api/v1/knowledge/update | Update knowledge base |
| GET | /api/v1/dashboard | Finding visualization |
| POST | /api/v1/analysis/cvss | Calculate CVSS v3.1 scores |
| GET | /api/v1/analysis/cve/{id} | Look up CVE |
| GET | /api/v1/analysis/mitre/{cwe} | Map CWE to ATT&CK |
| POST | /api/v1/analysis/code-scan | Scan code for vulnerabilities |
| GET | /health | Health check |

Interactive API docs available at /docs when running the server.

---

## Authorization System

Every active scan requires a cryptographically-signed authorization token:

`json
{
  "version": "1.0",
  "token_id": "uuid-v4",
  "target": {
    "domains": ["example.com"],
    "ip_ranges": ["203.0.113.0/24"],
    "excluded": ["admin.example.com"]
  },
  "scope": ["port_scan", "ssl_tls_check", "cve_lookup"],
  "expiry_unix": 1751241600,
  "approver_name": "Jane Doe",
  "operator_name": "John Smith",
  "restrictions": {
    "max_concurrent_requests": 10,
    "no_exploitation": true,
    "no_dos": true,
    "testing_window": {
      "start_utc": "09:00",
      "end_utc": "17:00",
      "days": ["mon", "tue", "wed", "thu", "fri"]
    }
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "<base64-encoded>",
    "signature_bytes": "<base64-encoded>",
    "signed_at_unix": 1751155200
  }
}
`

The authorization gate performs **10 verification checks**: signature validity, expiry, revocation, target authorization, scope authorization, testing window, path exclusions, exploitation restrictions, and more. Any check failure returns AuthorizationError with a specific reason.

---

## Configuration

All configuration is via environment variables (.env file):

| Variable | Description | Default |
|----------|-------------|---------|
| LLM_PROVIDER | Primary LLM: claude, openai, or ollama | claude |
| CLAUDE_API_KEY | Anthropic API key | - |
| OPENAI_API_KEY | OpenAI API key | - |
| OLLAMA_BASE_URL | Ollama server URL | http://localhost:11434 |
| VIRUSTOTAL_API_KEY | VirusTotal API key (4 req/min free) | - |
| SHODAN_API_KEY | Shodan API key | - |
| NVD_API_KEY | NIST NVD API key | - |
| PHISHTANK_API_KEY | PhishTank API key | - |
| ENCRYPTION_KEY | AES-256-GCM master key for DB encryption | - |
| ZAP_API_URL | OWASP ZAP daemon URL | http://localhost:8090 |
| DB_PATH | SQLite database path | data/grey_hat_agent.db |
| LOG_LEVEL | Logging level: DEBUG, INFO, WARNING, ERROR | INFO |
| CORS_ALLOWED_ORIGINS | Comma-separated CORS origins (or * for dev) | * |

> See .env.example for the complete list with signup links for each API.

---

## Project Structure

`
grey-hat-security-agent/
+-- core/
|   +-- auth/              # Authorization token system (Ed25519)
|   +-- intel/             # Threat intelligence feeds (6 clients)
|   +-- scanner/           # Active assessment tools (nmap, ZAP, nuclei, sslyze)
|   +-- analysis/          # CVSS v3.1, CVE matcher, MITRE ATT&CK
|   +-- reporting/         # Report generator, PDF renderer, templates
|   +-- knowledge/         # Self-learning pipeline + scheduler
+-- models/                # SecRoBERTa, CodeBERT, LLM provider
+-- api/                   # FastAPI REST API (19 endpoints)
+-- cli/                   # Typer CLI (9 commands)
+-- db/                    # SQLAlchemy models + AES-256-GCM encryption
+-- config/                # Pydantic Settings with env validation
+-- utils/                 # Crypto and helper utilities
+-- tests/                 # 87 passing tests
+-- data/                  # Local CVE mirror, model cache, reports
+-- docs/                  # Research documents
+-- .github/workflows/     # CI/CD pipeline
+-- Dockerfile             # Container deployment
+-- docker-compose.yml     # Agent + ZAP + Ollama
+-- setup.ps1              # Windows setup script
+-- LICENSE                # MIT License
+-- SECURITY.md            # Security policy
+-- CONTRIBUTING.md        # Contribution guide
+-- requirements.txt       # Python dependencies
+-- .env.example           # Environment variable template
+-- .gitignore             # Git ignore rules
`

---

## Testing

`ash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=core --cov=models --cov=db --cov=config --cov=utils --cov-report=term-missing

# Run specific test class
python -m pytest tests/test_comprehensive.py::TestAuthToken -v
python -m pytest tests/test_comprehensive.py::TestCVSS -v
python -m pytest tests/test_comprehensive.py::TestAuthGate -v
`

**Test Coverage**: Auth tokens (sign/verify/tamper/expiry/scope), CVSS v3.1 (6 NIST vectors), crypto (Ed25519, AES-256-GCM, SHA-256), risk scoring, MITRE mapping, CodeBERT (7 CWE patterns), SecRoBERTa (heuristic fallback), LLM caching, report formatting, DB models, encryption, config validation.

---

## Deployment

### Docker Compose (Recommended)

`ash
# Start all services
docker-compose up -d

# Agent API on http://localhost:8000
# OWASP ZAP on http://localhost:8090
# Ollama on http://localhost:11434

# View logs
docker-compose logs -f agent
`

### Manual

`ash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python main.py db-init

# Run API server
uvicorn api.main:app --host 0.0.0.0 --port 8000
`

### GitHub Actions CI

The included .github/workflows/ci.yml runs:
1. **Lint** with uff
2. **Type check** with mypy
3. **Unit tests** with pytest

---

## Security Policy

See [SECURITY.md](SECURITY.md) for:

- Vulnerability reporting procedure
- Responsible disclosure timeline
- Security architecture overview (auth gate, encryption, sandbox, audit trail)
- Deployment security best practices
- Known limitations

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development workflow
- Code style guide
- Testing requirements
- Adding new threat intel sources
- Adding new scanner modules
- Adding new LLM providers
- Pull request checklist

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.11+ |
| API Framework | FastAPI | 0.111+ |
| CLI | Typer | 0.12+ |
| Database | SQLite + SQLAlchemy | 2.0+ |
| Encryption | cryptography (AES-256-GCM, Ed25519) | 42+ |
| ML | HuggingFace Transformers + PyTorch | 4.41+ / 2.3+ |
| LLM | Anthropic Claude / OpenAI GPT-4o / Ollama | - |
| PDF Reports | ReportLab | 4.2+ |
| Port Scanner | python-nmap | 0.7+ |
| Web Scanner | OWASP ZAP API | 0.3+ |
| Docker SDK | docker | 7.0+ |

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <strong>Authorized use only.</strong> Every active scan requires a signed authorization token.<br>
  See <a href="docs/LEGAL-COMPLIANCE-RESEARCH.md">Legal Compliance Research</a> for applicable laws.
</p>
