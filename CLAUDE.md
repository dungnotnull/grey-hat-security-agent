# CLAUDE.md — grey-hat-security-agent

## Project Identity
- **Name**: grey-hat-security-agent
- **Tagline**: Authorized Cybersecurity Research & Red-Team Intelligence Agent
- **Status**: Phase 0 — Research & Environment Setup
- **Folder**: `D:\Dungchan\11\`

## Core Problem
Cybersecurity professionals and bug-bounty hunters spend enormous time manually aggregating threat intelligence, discovering in-scope vulnerabilities, and writing standardized reports. Meanwhile, scam/phishing infrastructure operates at machine speed while human defenders remain slow. This agent solves the defender's bottleneck: it continuously ingests security research (CVEs, ArXiv papers, GitHub PoCs, MITRE ATT&CK updates), performs authorized assessments exclusively against systems with explicit written permission, and generates professional CVSS-scored vulnerability reports — accelerating the responsible-disclosure pipeline without ever acting autonomously against unauthorized systems.

**Ethics boundary (non-negotiable):** Scam/phishing domain discovery is strictly read-only threat intelligence — catalog, score, and report to authorities (CERT, Google Safe Browsing). No unilateral attack capabilities against any target, even malicious ones.

## Architecture Summary
- **Platform**: Python 3.11, async FastAPI backend, Typer CLI interface
- **ML Stack**: SecRoBERTa (CVE NLP) + CodeBERT (vulnerable code detection) + CVSS v3.1 calculator
- **Local SLM**: Mistral-7B-Instruct via Ollama — offline fallback for report drafting and CVE analysis
- **External APIs**: Claude API (primary), GPT-4o (fallback), VirusTotal API, Shodan API, NVD/NIST API
- **Storage**: SQLite + AES-256-GCM application-layer encryption for all findings and auth tokens
- **Data Feeds**: NVD CVE feed, MITRE ATT&CK STIX, OpenPhish, PhishTank, URLhaus, Exploit-DB

## Key Technical Decisions
1. **Authorization gate is mandatory**: Every active scan/test requires a signed JSON authorization token (target + scope + expiry + approver_signature) stored in SQLite before any assessment begins.
2. **Read-only threat intelligence**: Scam/phishing domain discovery never issues attacks — agent catalogs, scores, and submits reports to Google Safe Browsing API and CERT authorities.
3. **Pluggable LLM backend**: `LLM_PROVIDER` env var selects Claude API → GPT-4o → Ollama (Mistral-7B) in fallback chain.
4. **CVSS v3.1 scoring engine**: Standalone Python implementation — no external dependency for vulnerability scoring.
5. **Docker sandbox for PoC testing**: Any proof-of-concept code runs exclusively inside an isolated Docker container with `--network none` flag.
6. **Graduated intervention pattern**: observe (passive recon) → analyze (local ML processing) → report (human review required before any active test).
7. **Self-improving loop**: crawl4ai weekly pipeline updates SECOND-KNOWLEDGE-BRAIN.md from ArXiv cs.CR, NVD, MITRE ATT&CK, Exploit-DB.

## External LLM API Integrations

| Provider | Purpose | Config Key | Model |
|----------|---------|------------|-------|
| Anthropic Claude | Primary: CVE analysis, report drafting, threat classification, remediation suggestions | `CLAUDE_API_KEY` | claude-opus-4-8 |
| OpenAI GPT-4o | Fallback: same tasks when Claude API unavailable | `OPENAI_API_KEY` | gpt-4o |
| Ollama (local) | Offline fallback: Mistral-7B-Instruct | `OLLAMA_BASE_URL` | mistral:7b-instruct |

## HuggingFace Models in Use

| Model ID | Purpose | Link |
|----------|---------|------|
| `jackaduma/SecRoBERTa` | Security domain NLP: CVE text classification, severity extraction, phishing content detection | https://huggingface.co/jackaduma/SecRoBERTa |
| `microsoft/codebert-base` | Vulnerability pattern detection in source code snippets (SQLi, path traversal, buffer overflow) | https://huggingface.co/microsoft/codebert-base |
| `mistralai/Mistral-7B-Instruct-v0.3` | Local offline report drafting and CVE remediation suggestions via Ollama | https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3 |

## Current Active Development Tasks
- [ ] Set up Python 3.11 virtual environment and dependency scaffold
- [ ] Implement JSON authorization token schema with signature verification
- [ ] Build NVD CVE feed ingestion and delta-update pipeline
- [ ] Integrate VirusTotal API for domain threat scoring
- [ ] Build standalone CVSS v3.1 calculator module
- [ ] Implement crawl4ai weekly self-update pipeline (ArXiv cs.CR + NVD + Exploit-DB)
- [ ] Create CLI interface: `intel`, `scan`, `report`, `authorize`, `update` commands
- [ ] Write Docker sandbox executor for PoC code testing
- [ ] Build LLM report generator (Claude → GPT-4o → Ollama fallback chain)
- [ ] Implement PhishTank/OpenPhish/URLhaus feed aggregator (read-only)
- [ ] Build SQLite + AES-256 encrypted storage layer

## Related Files
- [`PROJECT-detail.md`](./PROJECT-detail.md) — full technical specification
- [`PROJECT-DEVELOPMENT-PHASE-TRACKING.md`](./PROJECT-DEVELOPMENT-PHASE-TRACKING.md) — phase-by-phase roadmap
- [`SECOND-KNOWLEDGE-BRAIN.md`](./SECOND-KNOWLEDGE-BRAIN.md) — self-improving cybersecurity knowledge base
