# Security Policy

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them securely via one of these methods:

1. **Email**: Send a description of the vulnerability to the project maintainers (see README for contact info)
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature at [https://github.com/REPO/security/advisories/new](https://github.com/REPO/security/advisories/new)

Please include the following information:

- Type of vulnerability (e.g., buffer overflow, SQL injection, cross-site scripting)
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Responsible Disclosure Timeline

- We will acknowledge your report within 48 hours
- We will provide a more detailed response within 7 days indicating the next steps
- We will keep you informed of the progress towards a fix
- We may ask for additional information or guidance
- We aim to release a fix within 30 days of confirmation

## Security Architecture

This project includes several built-in security mechanisms:

### Authorization Gate
All active scanning requires a valid Ed25519-signed authorization token. Scans without proper authorization are blocked at the gate level. See docs/AUTH-TOKEN-SCHEMA.md for the full specification.

### Data Encryption
All sensitive data stored in SQLite is encrypted at the application layer using AES-256-GCM. The master encryption key is stored in .env and never committed to version control.

### LLM Hallucination Guard
All CVE IDs generated in LLM reports are verified against the local NVD mirror. Any CVE ID not found in the database is stripped from the report before output.

### Docker Sandbox
Proof-of-concept code execution runs inside isolated Docker containers with --network none, read-only filesystems, and strict memory/CPU limits.

### Audit Trail
Every action (scan, token creation, report generation) is logged in an immutable append-only audit table with timestamp, actor, target, and token hash.

## Security Best Practices for Deployment

1. **Never commit .env files** — Always use .env.example as a template
2. **Use strong encryption keys** — Generate with python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
3. **Restrict API access** — Use llow_origins in production, not *
4. **Enable HTTPS** — Use a reverse proxy (nginx/Caddy) with TLS
5. **Rotate API keys** — Regularly rotate VirusTotal, Shodan, and LLM API keys
6. **Review token expiry** — Set reasonable expiry times on authorization tokens
7. **Audit regularly** — Review the udit_log table for suspicious activity

## Known Limitations

- The free-tier VirusTotal API is limited to 4 requests/minute
- LLM-generated reports may contain inaccurate information despite the hallucination guard
- The authorization gate protects against unauthorized scanning but does not encrypt scan results at rest (encrypted fields are limited to tokens and sensitive findings)
- The sandbox executor requires Docker to be installed and running
