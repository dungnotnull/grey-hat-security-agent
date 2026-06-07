# PROJECT-DEVELOPMENT-PHASE-TRACKING.md — grey-hat-security-agent

## Overview
This document tracks the phase-by-phase development roadmap for **grey-hat-security-agent** — an authorized cybersecurity research and red-team intelligence assistant. Each phase builds on the previous and has explicit success criteria before proceeding.

**Total estimated timeline**: 16 weeks
**Current phase**: ALL PHASES COMPLETE ✅

---

## Phase 0: Research & Environment Setup ✅ COMPLETE
**Timeline**: Week 1–2
**Goal**: Establish foundations, validate toolchain, understand legal requirements

### Deliverables ✅
- ✅ Project directory structure with 59 Python source files
- ✅ .env.example with 35+ documented config keys and signup page links
- ✅ Authorization token JSON schema specification document (docs/AUTH-TOKEN-SCHEMA.md)
- ✅ Legal compliance research document (docs/LEGAL-COMPLIANCE-RESEARCH.md)
- ✅ Threat intelligence API survey (docs/THREAT-INTELLIGENCE-API-SURVEY.md)
- ✅ Scanner tools evaluation (docs/SCANNER-TOOLS-EVALUATION.md)
- ✅ ML model & report template survey (docs/MODEL-AND-TEMPLATE-SURVEY.md)
- ✅ Dependency requirements.txt with all packages installed in venv
- ✅ Ollama setup documented (user runs ollama pull mistral:7b-instruct manually)
- ✅ README.md with quickstart, architecture, CLI reference
- ✅ setup.ps1 automated environment setup script
- ✅ .gitignore for sensitive files

### Success Criteria ✅
- ✅ python -m pytest tests/ -v passes — **85/85 tests passing**
- ✅ All API keys from .env.example documented with links to signup pages

---

## Phase 1: MVP — Core Loop Working ✅ COMPLETE
**Timeline**: Week 3–6
**Goal**: Working end-to-end pipeline for both operating modes

### Tasks ✅
- ✅ AuthToken Pydantic model with Ed25519 signing/verification
- ✅ AuthorizationGate with 10 enforcement checks (signature, expiry, scope, target, path, testing window, exploitation restrictions)
- ✅ SQLite database with 9 tables + AES-256-GCM encryption layer
- ✅ PhishTank, OpenPhish, URLhaus async feed clients
- ✅ VirusTotal API wrapper with rate limiting and caching
- ✅ Shodan API client
- ✅ Composite risk score calculator (30% VT + 20% feeds + 25% NLP + 15% age + 10% WHOIS)
- ✅ nmap wrapper with structured Service objects
- ✅ SSL/TLS checker using sslyze
- ✅ OWASP ZAP scanner integration via REST API
- ✅ nuclei scanner subprocess integration
- ✅ Scanner orchestrator coordinating multi-phase scans
- ✅ CVE matcher against local NVD mirror
- ✅ MITRE ATT&CK mapper (CWE→TTP and service→TTP)
- ✅ Docker sandbox executor with --network none isolation
- ✅ LLM report generator with fallback chain
- ✅ Typer CLI with 9 commands (intel score/check, scan run/dry-run, report generate/email-draft, authorize keygen/create/sign/verify, update, db-init, sandbox)
- ✅ FastAPI REST API with 14 endpoints (auth, intel, scan, report, analysis, knowledge, dashboard, health)
- ✅ Domain risk scoring with breakdown

### Success Criteria ✅
- ✅ Auth token system cryptographically enforced before any active scan
- ✅ 85 tests passing covering all core modules
- ✅ CLI and API fully functional
- ✅ All __init__.py files have proper exports

---

## Phase 2: ML/AI Integration ✅ COMPLETE
**Timeline**: Week 7–10
**Goal**: Local ML models enhance accuracy and reduce dependency on external APIs

### Tasks ✅
- ✅ SecRoBERTa inference wrapper with heuristic fallback
- ✅ CodeBERT vulnerability scanner with CWE pattern detection (8 CWE types)
- ✅ CVSS v3.1 calculator with spec-correct Roundup function (passes all NIST test vectors)
- ✅ MITRE ATT&CK mapper with CWE→TTP and service→TTP mappings + hardcoded fallback
- ✅ Docker sandbox executor (--network none, read-only fs, memory/CPU limits)

### Success Criteria ✅
- ✅ SecRoBERTa heuristic severity classification works for all 5 levels
- ✅ CodeBERT detects SQLi, path traversal, hardcoded creds, OS command injection, XSS, SSRF patterns
- ✅ CVSS calculator passes all NIST reference vectors (9.8, 7.5, 5.3, 3.1, 0.0, 5.5)
- ✅ ATT&CK technique IDs appear in generated reports
- ✅ Docker sandbox executes code safely and destroys containers

---

## Phase 3: External LLM API Integration ✅ COMPLETE
**Timeline**: Week 11–12
**Goal**: Professional-quality report generation powered by Claude API with robust fallback

### Tasks ✅
- ✅ Anthropic Claude SDK integration with async client
- ✅ OpenAI GPT-4o fallback integration
- ✅ Ollama/Mistral-7B offline fallback
- ✅ LLM response caching with 7-day TTL (in-memory + SHA-256 key)
- ✅ CVE ID hallucination guard (verify against NVD mirror)
- ✅ Prompt template library: executive summary, finding narrative, remediation, threat intel, disclosure email
- ✅ Report generation in Markdown, PDF (ReportLab), and HTML formats
- ✅ PDF renderer with cover page, TOC, severity tables, finding details
- ✅ HTML dashboard report with sortable finding table
- ✅ Responsible disclosure email draft generator
- ✅ CLI command: report email-draft --scan-id <id> --org <name>

### Success Criteria ✅
- ✅ Full markdown + PDF + HTML report generation pipeline
- ✅ CVE ID verification guard strips hallucinated IDs
- ✅ Fallback chain: Claude → GPT-4o → Ollama produces valid output at each level
- ✅ Template-based fallback generates coherent reports without any LLM
- ✅ 85 tests passing including report format tests

---

## Phase 4: Self-Improving Knowledge Loop ✅ COMPLETE
**Timeline**: Week 13–14
**Goal**: Agent autonomously expands its knowledge base from live security research feeds

### Tasks ✅
- ✅ KnowledgeUpdater class with 5 sources (ArXiv, NVD, Exploit-DB, MITRE ATT&CK, HuggingFace)
- ✅ ArXiv cs.CR crawler with relevance search
- ✅ NVD CVE delta feed with modStartDate/modEndDate parameters
- ✅ Exploit-DB CSV parser
- ✅ MITRE ATT&CK STIX bundle parser
- ✅ HuggingFace Papers API monitor
- ✅ Delta update tracking (last_run_file)
- ✅ APScheduler integration for weekly auto-updates
- ✅ CLI command: update --source all|arxiv|nvd|exploitdb|mitre|huggingface
- ✅ API endpoint: POST /api/v1/knowledge/update

### Success Criteria ✅
- ✅ update command runs without errors
- ✅ APScheduler configured for Sunday 02:00 UTC weekly + monthly MITRE
- ✅ CLI and API both support knowledge updates
- ✅ Deduplication by DOI/CVE-ID in knowledge updater

---

## Phase 5: Testing, Polish & Deployment ✅ COMPLETE
**Timeline**: Week 15–16
**Goal**: Production-ready, tested, and deployable agent

### Tasks ✅

#### Testing ✅
- ✅ 85 unit tests covering auth, CVSS, crypto, helpers, risk score, MITRE mapper, CodeBERT, SecRoBERTa, LLM provider, report generator, templates, DB models, encryption, config, all module imports
- ✅ CVSS calculator passes all NIST test vectors
- ✅ Auth token signing/verification/tampering/expiry tests
- ✅ Authorization gate enforcement tests (8 scenarios)
- ✅ CodeBERT pattern detection tests (7 CWE patterns)
- ✅ SecRoBERTa heuristic fallback tests (5 severity levels + phishing)

#### Polish ✅
- ✅ Rich CLI progress bars and colored output
- ✅ Comprehensive error messages with remediation hints
- ✅ --dry-run flag for scan command
- ✅ FastAPI dashboard endpoint /api/v1/dashboard
- ✅ CVSS calculation API endpoint POST /api/v1/analysis/cvss
- ✅ CVE lookup API endpoint GET /api/v1/analysis/cve/{cve_id}
- ✅ MITRE mapping API endpoint GET /api/v1/analysis/mitre/{cwe_id}
- ✅ Code scan API endpoint POST /api/v1/analysis/code-scan

#### Documentation ✅
- ✅ README.md with installation, quickstart guide, CLI reference
- ✅ Ethics and legal notice in README
- ✅ .env.example with comments for every variable (40+ config keys)
- ✅ FastAPI auto-generated docs at /docs endpoint

#### Deployment ✅
- ✅ Dockerfile for containerized deployment
- ✅ docker-compose.yml: agent + OWASP ZAP + Ollama services
- ✅ Windows installer script (setup.ps1)
- ✅ GitHub Actions CI: lint (ruff), type check (mypy), unit tests
- ✅ Health check endpoint: GET /health

### Success Criteria ✅
- ✅ pytest tests/ -v passes: 85/85 tests passing
- ✅ Docker Compose configuration ready (agent + ZAP + Ollama)
- ✅ CI/CD pipeline configured (ruff + mypy + pytest)
- ✅ All CLI commands functional (intel, scan, report, authorize, update, db-init, sandbox)
- ✅ Auth bypass attempt returns AuthorizationError with no scan data returned

---

## Progress Summary

| Phase | Status | Week | Key Milestone |
|-------|--------|------|---------------|
| 0 — Research & Setup | ✅ COMPLETE | 1–2 | Environment ready, schemas designed, 85 tests passing |
| 1 — MVP Core Loop | ✅ COMPLETE | 3–6 | All CLI/API commands working E2E |
| 2 — ML/AI Integration | ✅ COMPLETE | 7–10 | SecRoBERTa + CodeBERT + CVSS active |
| 3 — External LLM API | ✅ COMPLETE | 11–12 | Professional PDF/HTML/MD reports generated |
| 4 — Self-Learning Loop | ✅ COMPLETE | 13–14 | Weekly auto-update pipeline active |
| 5 — Testing & Deploy | ✅ COMPLETE | 15–16 | Docker Compose + 85 test suite passing |

---

## Key Files

| Path | Purpose |
|------|---------|
| core/auth/token.py | AuthToken Pydantic model, Ed25519 signing/verification |
| core/auth/gate.py | AuthorizationGate with 10 enforcement checks |
| core/intel/ | 7 intel clients (PhishTank, OpenPhish, URLhaus, VirusTotal, Shodan, risk_score, rate_limiter) |
| core/scanner/ | nmap, sslyze, ZAP, nuclei, orchestrator, sandbox |
| core/analysis/cvss.py | CVSS v3.1 calculator with Roundup (fixed for NIST vectors) |
| core/analysis/cve_matcher.py | CVE matcher against local NVD mirror |
| core/analysis/mitre_mapper.py | CWE→ATT&CK and service→ATT&CK mapping |
| core/knowledge/updater.py | crawl4ai-based 5-source knowledge updater |
| core/knowledge/scheduler.py | APScheduler for weekly auto-updates |
| core/reporting/generator.py | LLM-powered report generator with hallucination guard |
| core/reporting/pdf_renderer.py | ReportLab PDF renderer with cover page |
| core/reporting/templates.py | 5 LLM prompt templates + disclosure email template |
| models/llm_provider.py | Claude→GPT-4o→Ollama fallback chain with caching |
| models/secroberta.py | SecRoBERTa classifier with heuristic fallback |
| models/codebert.py | CodeBERT vulnerability scanner with pattern fallback |
| cli/main.py | Typer CLI with 9 commands |
| api/main.py | FastAPI app with 14 endpoints |
| db/models.py | 9 SQLAlchemy tables |
| db/encryption.py | AES-256-GCM field encryption |
| db/session.py | Async + sync SQLAlchemy session management |
| config/settings.py | Pydantic Settings with 40+ config keys |
| utils/crypto.py | Ed25519, AES-256-GCM, SHA-256, canonical JSON |
| utils/helpers.py | Rate limiting, retry, domain/IP validation |
| tests/test_comprehensive.py | 85 passing tests |
| Dockerfile | Container deployment |
| docker-compose.yml | Agent + ZAP + Ollama services |
| .github/workflows/ci.yml | CI/CD pipeline (lint + type check + test) |
| setup.ps1 | Windows environment setup script |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| VirusTotal API rate limits (free tier: 4 req/min) | High | Medium | Queue + rate limiter; upgrade to commercial tier if needed |
| OWASP ZAP daemon stability issues | Medium | Medium | Health-check + auto-restart in Docker Compose |
| Ollama Mistral-7B report quality too low | Medium | Low | Fine-tune on HackerOne public disclosures; use GPT-4o as primary fallback |
| NVD API downtime during updates | Low | Low | Local mirror means agent functions; retry with exponential backoff |
| Legal ambiguity in authorization token enforcement | Low | High | Require signed tokens with real Ed25519 signatures; clear user warning at startup |
| LLM hallucinating CVE IDs in reports | Medium | High | Post-process all LLM output: verify every CVE ID against local NVD mirror before including in report |
