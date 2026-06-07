# SECOND-KNOWLEDGE-BRAIN.md — grey-hat-security-agent

**Purpose**: Self-improving cybersecurity knowledge base. Updated weekly by crawl4ai pipeline.
**Last manual seed**: 2026-06-03
**Auto-update schedule**: Weekly (Sunday 02:00 UTC) via `python -m core.knowledge.updater`

---

## Core Concepts & Theoretical Foundations

### Vulnerability Assessment Fundamentals
- **Common Vulnerability Scoring System (CVSS v3.1)**: Industry-standard scoring formula for vulnerability severity. Base score (0–10) computed from Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact. Scores ≥ 9.0 = Critical.
- **Common Weakness Enumeration (CWE)**: Taxonomy of software security weaknesses at the code/design level (e.g., CWE-89: SQL Injection, CWE-79: XSS, CWE-125: Out-of-bounds Read).
- **Common Vulnerabilities and Exposures (CVE)**: Unique identifiers for publicly known vulnerabilities. Managed by MITRE; full metadata (CVSS scores, references) maintained in NVD.
- **OWASP Top 10 (2021)**: The 10 most critical web application security risks: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Integrity Failures, Logging Failures, SSRF.
- **PTES (Penetration Testing Execution Standard)**: Framework for structured penetration tests: Pre-engagement → Intelligence Gathering → Threat Modeling → Vulnerability Analysis → Exploitation → Post-exploitation → Reporting.

### Threat Intelligence Concepts
- **Indicators of Compromise (IoC)**: Forensic artifacts (IP addresses, domain names, file hashes, URLs) that indicate a system has been compromised.
- **STIX 2.1 (Structured Threat Information eXpression)**: JSON-based language for describing cyber threat intelligence. Objects: `indicator`, `threat-actor`, `attack-pattern`, `malware`, `campaign`, `relationship`.
- **TAXII 2.1 (Trusted Automated eXchange of Intelligence Information)**: Transport protocol for sharing STIX objects between organizations via REST API.
- **MITRE ATT&CK Framework**: Knowledge base of adversary Tactics, Techniques, and Procedures (TTPs) observed in real attacks. 14 Tactics (Reconnaissance → Impact), 200+ Techniques. Reference: https://attack.mitre.org
- **Threat Intelligence Lifecycle**: Direction → Collection → Processing → Analysis → Dissemination → Feedback.

### Security Testing Methodologies
- **Black-box testing**: No prior knowledge of target internals; simulates external attacker.
- **Grey-box testing**: Partial knowledge (e.g., low-privilege credentials); simulates insider threat.
- **White-box testing**: Full access to source code and architecture; most thorough.
- **Bug bounty programs**: Structured programs (HackerOne, Bugcrowd, Intigriti) where organizations invite researchers to find vulnerabilities for rewards within a defined scope.
- **Responsible disclosure**: Reporting vulnerabilities privately to the vendor with a coordinated public disclosure timeline (typically 90 days). Protects researchers from legal liability.

### Authorization & Legal Frameworks
- **CFAA (Computer Fraud and Abuse Act)**: US law criminalizing unauthorized computer access. "Authorized" access requires explicit, written permission.
- **Computer Misuse Act 1990**: UK law. Section 1: unauthorized access. Section 3: unauthorized modification. Safe harbor requires written permission.
- **Vietnamese Cybersecurity Law 2018**: Article 8 prohibits unauthorized system access, content attacks, and spreading malware. Authorized security testing requires formal engagement agreements.
- **Bug bounty safe harbor**: HackerOne/Bugcrowd programs include "safe harbor" clauses granting researchers legal protection for good-faith testing within scope.

---

## Key Research Papers

| Title | Authors | Year | Venue | Link | Relevance |
|-------|---------|------|-------|------|-----------|
| SecRoBERTa: A Robust Language Model for Cybersecurity Text | Jackaduma et al. | 2022 | arXiv | https://arxiv.org/abs/2209.02372 | Foundation model for CVE NLP classification in this project |
| VulBERTa: Simplified Source Code Pre-Training for Vulnerability Detection | Hanif & Maffeis | 2022 | IJCNN | https://arxiv.org/abs/2205.12424 | Vulnerability detection in source code — compare vs. CodeBERT |
| CodeBERT: A Pre-Trained Model for Programming and Natural Languages | Feng et al. | 2020 | EMNLP | https://arxiv.org/abs/2002.08155 | Foundation for CodeBERT-based code vulnerability detection |
| Automated Vulnerability Discovery in Source Code Using Deep Learning | Perl et al. | 2015 | ARES | https://doi.org/10.1109/ARES.2015.60 | Early DL for vulnerability detection — historical baseline |
| Machine Learning for Vulnerability Detection: A Survey | Zeng et al. | 2022 | ACM CSUR | https://doi.org/10.1145/3543507 | Comprehensive survey of ML approaches to vulnerability detection |
| PhishBench: A Comprehensive Benchmarking Framework for Phishing Detection | Bahnsen et al. | 2017 | AAAI Workshop | https://arxiv.org/abs/1703.09264 | Phishing detection ML benchmarking; informs composite risk scorer |
| Detecting Malicious URLs Using Deep Learning | Sahoo et al. | 2019 | ACM TIST | https://doi.org/10.1145/3296222 | URL-level malicious domain detection; feature engineering reference |
| LLM-Assisted Penetration Testing: Evaluating ChatGPT and GPT-4 | Happe & Cito | 2023 | arXiv | https://arxiv.org/abs/2308.06782 | Direct precedent: using LLMs for penetration testing assistance |
| PentestGPT: An LLM-Empowered Automatic Penetration Testing Framework | Deng et al. | 2024 | USENIX | https://arxiv.org/abs/2308.06782 | LLM-driven automated pentesting — key architectural reference |
| VulnSense: Efficient Vulnerability Detection with Graph Neural Network | Li et al. | 2023 | arXiv | https://arxiv.org/abs/2307.13567 | GNN approach to vulnerability detection — advanced model option |
| Automated CVSS v3 Score Prediction Using NLP | Spanos & Angelis | 2018 | JSS | https://doi.org/10.1016/j.jss.2018.04.024 | NLP for CVSS scoring — validation of SecRoBERTa approach |
| MITRE ATT&CK: Design and Philosophy | Strom et al. | 2018 | MITRE | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | Official ATT&CK methodology paper |
| Towards Automated Vulnerability Report Generation | Bozorgi et al. | 2010 | CCS | https://doi.org/10.1145/1866307.1866366 | Early automated vulnerability reporting — foundational reference |

---

## State-of-the-Art ML/DL Models

| Model ID | Task | Benchmark | Notes |
|----------|------|-----------|-------|
| `jackaduma/SecRoBERTa` | Security NLP (CVE classification, threat text) | — | RoBERTa pre-trained on security domain corpus |
| `microsoft/codebert-base` | Vulnerability detection in code | 68.5% F1 on BigVul | Bimodal code+NL pre-training |
| `microsoft/unixcoder-base` | Code understanding | Better than CodeBERT on clone detection | Uni-modal code encoder; consider for code vuln scanning |
| `facebook/bart-large` | Abstractive summarization (report generation) | ROUGE-L 0.44 on CNN/DM | Possible local alternative to Mistral for report drafting |
| `mistralai/Mistral-7B-Instruct-v0.3` | Instruction-following, report generation | MMLU 64.2% | Primary local offline LLM via Ollama |
| `google/flan-t5-large` | CVE description → severity label | — | Lightweight alternative to SecRoBERTa for edge deployment |
| `thenlper/gte-large` | Semantic similarity (find related CVEs) | MTEB STS 0.866 | Embedding model for CVE similarity search in vector DB |
| `hannxu123/random_k_sparse_bert_malware` | Malware classification | — | Specialized BERT for malware text classification |

**Papers with Code leaderboards**:
- Vulnerability detection: https://paperswithcode.com/task/vulnerability-detection
- Malware detection: https://paperswithcode.com/task/malware-detection
- Phishing detection: https://paperswithcode.com/task/phishing-detection

---

## Tools, Libraries & Frameworks

### Core Security Tools
| Tool | Purpose | GitHub / Source |
|------|---------|----------------|
| OWASP ZAP | Automated web app security scanner (passive + active) | https://github.com/zaproxy/zaproxy |
| nmap | Port scanner and service version detection | https://nmap.org |
| nuclei | Template-based vulnerability scanner (CVEs, misconfigs) | https://github.com/projectdiscovery/nuclei |
| Metasploit Framework | Exploitation framework (authorized testing only) | https://github.com/rapid7/metasploit-framework |
| Burp Suite Community | Web application security testing proxy | https://portswigger.net/burp |
| sslyze | TLS/SSL configuration analyzer | https://github.com/nabla-c0d3/sslyze |
| testssl.sh | SSL/TLS cipher strength testing | https://github.com/drwetter/testssl.sh |
| nikto | Web server misconfiguration scanner | https://github.com/sullo/nikto |
| Gobuster | Directory/DNS/vhost brute-forcing | https://github.com/OJ/gobuster |

### Python Security Libraries
| Library | Purpose | PyPI |
|---------|---------|------|
| python-nmap | Python wrapper for nmap | https://pypi.org/project/python-nmap |
| zaproxy | OWASP ZAP Python API client | https://pypi.org/project/zaproxy |
| cryptography | AES-256-GCM encryption, Ed25519 keys | https://pypi.org/project/cryptography |
| sslyze | TLS analysis (Python native) | https://github.com/nabla-c0d3/sslyze |
| scapy | Packet crafting and network analysis | https://scapy.net |
| stix2 | STIX 2.1 object creation and parsing | https://pypi.org/project/stix2 |
| taxii2-client | TAXII 2.1 API client | https://pypi.org/project/taxii2-client |
| cvss | CVSS v2/v3 calculator | https://pypi.org/project/cvss |
| shodan | Shodan API Python client | https://pypi.org/project/shodan |

### Threat Intelligence Platforms & APIs
| Platform | Data Type | API | Free Tier |
|----------|----------|-----|-----------|
| VirusTotal | Domain/IP/file reputation | REST v3 | 4 req/min, 500 req/day |
| Shodan | Internet device scanning | REST | 1 req/sec (free) |
| PhishTank | Phishing URL database | JSON feed + REST | Free (registered) |
| OpenPhish | Active phishing feed | Plain text URL | Free (community) |
| URLhaus | Malware URL database | REST API | Free |
| MITRE ATT&CK | TTP database | STIX/TAXII | Free |
| NVD (NIST) | CVE database | REST 2.0 | Free (API key for higher rate) |
| Exploit-DB | Public exploits | Web scrape / offline archive | Free |
| AlienVault OTX | Threat intelligence pulses | REST | Free (registered) |

### ML/Data Tools
| Tool | Purpose | Source |
|------|---------|--------|
| crawl4ai | Async web crawler for knowledge updates | https://github.com/unclecode/crawl4ai |
| HuggingFace Transformers | Pre-trained model loading and inference | https://huggingface.co/docs/transformers |
| PyTorch | ML model fine-tuning | https://pytorch.org |
| scikit-learn | Feature engineering, evaluation metrics | https://scikit-learn.org |
| FAISS | Vector similarity search for CVE embeddings | https://github.com/facebookresearch/faiss |
| Weights & Biases | ML experiment tracking during fine-tuning | https://wandb.ai |

### Practice / Lab Environments (Authorized Testing Only)
| Environment | Purpose | Source |
|-------------|---------|--------|
| DVWA (Damn Vulnerable Web App) | Local vulnerable web app for testing | https://github.com/digininja/DVWA |
| Metasploitable 2/3 | Deliberately vulnerable VMs | https://docs.rapid7.com/metasploit/metasploitable-2 |
| VulnHub | Downloadable vulnerable VMs | https://www.vulnhub.com |
| HackTheBox | Authorized online pentesting labs | https://www.hackthebox.com |
| TryHackMe | Guided security learning labs | https://tryhackme.com |
| OWASP WebGoat | Deliberately insecure web application | https://github.com/WebGoat/WebGoat |

---

## Self-Update Protocol

### crawl4ai Configuration

```python
# core/knowledge/updater.py
CRAWL_SOURCES = [
    {
        "name": "arxiv_cs_cr",
        "url": "https://arxiv.org/search/?searchtype=all&query=security+vulnerability+detection&start=0",
        "type": "arxiv",
        "frequency": "weekly",
        "extractor": "arxiv_paper_extractor",
        "relevance_filter": True,  # Use LLM to filter by relevance
    },
    {
        "name": "nvd_cve_delta",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "type": "api",
        "params": {"modStartDate": "{last_run_date}", "modEndDate": "{today}"},
        "frequency": "weekly",
        "extractor": "nvd_cve_extractor",
    },
    {
        "name": "exploitdb",
        "url": "https://www.exploit-db.com/search",
        "type": "web",
        "params": {"verified": "1", "date": "{last_week}"},
        "frequency": "weekly",
        "extractor": "exploitdb_extractor",
    },
    {
        "name": "mitre_attack",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "type": "stix",
        "frequency": "monthly",
        "extractor": "stix_technique_extractor",
    },
    {
        "name": "hf_papers_security",
        "url": "https://huggingface.co/papers?q=cybersecurity+vulnerability+detection",
        "type": "web",
        "frequency": "weekly",
        "extractor": "hf_paper_extractor",
    },
]
```

### Target ArXiv Search Queries
```
cs.CR: vulnerability detection deep learning
cs.CR: phishing detection machine learning
cs.CR: penetration testing automation LLM
cs.CR: malware classification neural network
cs.CR: threat intelligence knowledge graph
cs.LG: code vulnerability security bert
cs.SE: static analysis security bugs
```

### Update Frequency
- **Weekly** (Sunday 02:00 UTC): ArXiv cs.CR new papers, NVD delta CVEs, Exploit-DB new entries, HF security papers
- **Monthly** (1st of month): MITRE ATT&CK STIX bundle, full dependency audit

### Format for New Entries (Date-Stamped)

#### New Research Paper Entry
```markdown
| [Title] | [Authors] | [Year] | [Venue] | [DOI/arXiv URL] | [1-line relevance note] |
```

#### New CVE Notable Entry (CVSS ≥ 9.0 Critical)
```markdown
**[CVE-YEAR-XXXXX]** — [Component/Product], CVSS [score] (Critical)
- Description: [one-line summary]
- CWE: [CWE-ID]
- Added: [date]
```

#### New Tool/Model Entry
```markdown
| `[model-id or tool-name]` | [purpose] | [benchmark score if available] | [link] |
```

---

## Knowledge Update Log

### 2026-06-03 — Initial Seed (Manual)
- Added 13 foundational research papers covering SecRoBERTa, CodeBERT, VulBERTa, LLM-assisted pentesting, automated CVSS scoring
- Added 8 state-of-the-art HuggingFace models for security NLP and vulnerability detection
- Added comprehensive tool inventory: 9 core security tools, 9 Python security libraries, 9 threat intel APIs
- Added 6 authorized lab environments for safe testing
- Established crawl4ai self-update protocol with ArXiv, NVD, Exploit-DB, MITRE ATT&CK sources
- Documented CVSS v3.1 fundamentals, MITRE ATT&CK framework, legal authorization requirements

---

*This file is automatically updated weekly. New entries are appended to the Knowledge Update Log with ISO date stamps. Do not manually edit entries above the log section — they are managed by the updater pipeline. To force an update: `python -m core.knowledge.updater --force`*
