# Contributing to grey-hat-security-agent

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to treat everyone with respect and professionalism. Harassment, discrimination, and abusive behavior will not be tolerated.

## Getting Started

1. Fork the repository
2. Clone your fork: git clone https://github.com/YOUR_USERNAME/grey-hat-security-agent.git
3. Create a virtual environment: python -m venv venv
4. Activate: .\venv\Scripts\activate (Windows) or source venv/bin/activate (Linux/Mac)
5. Install dependencies: pip install -r requirements.txt
6. Copy config: copy .env.example .env and fill in your API keys
7. Run tests: python -m pytest tests/ -v

## Development Workflow

1. Create a feature branch: git checkout -b feature/your-feature-name
2. Make your changes
3. Add tests for your changes
4. Run the full test suite: python -m pytest tests/ -v
5. Run linting: uff check .
6. Commit with a descriptive message
7. Push to your fork and open a Pull Request

## Code Style

- Python 3.11+ with type hints
- Line length: 120 characters
- Use uff for linting: uff check .
- Use mypy for type checking: mypy --ignore-missing-imports core/ models/ api/ cli/
- Follow PEP 8 naming conventions
- Add docstrings to all public functions and classes

## Testing

- All new features must include tests
- Run tests before submitting: python -m pytest tests/ -v
- Aim for meaningful coverage of core logic, not just import checks
- Use pytest fixtures for database setup when needed
- Mock external API calls (VirusTotal, Shodan, etc.) in tests

## Adding New Features

### Threat Intelligence Sources
1. Create a new client in core/intel/ following the pattern in irustotal.py
2. Add rate limiting in utils/helpers.py
3. Integrate into isk_score.py if applicable
4. Add config key in config/settings.py
5. Add .env.example entry with signup link
6. Write tests

### Scanner Modules
1. Create a new scanner in core/scanner/ following the pattern in 
map_wrapper.py
2. All scanner methods must accept 	oken: AuthToken and gate: AuthorizationGate
3. Call gate.authorize(token, target, scope) before any active scanning
4. Return structured dataclass results
5. Add to orchestrator.py full_scan pipeline
6. Write tests

### LLM Providers
1. Add provider config to PROVIDERS list in models/llm_provider.py
2. Implement _call_<provider> method
3. Add config key to config/settings.py
4. Write tests with mocked API responses

## Security Considerations

- **Never commit API keys, passwords, or tokens** — Use .env for secrets
- **All active scanning requires authorization tokens** — See docs/AUTH-TOKEN-SCHEMA.md
- **Verify CVE IDs** — LLM-generated reports must pass through the hallucination guard
- **Sandbox PoC execution** — Any proof-of-concept code must run in Docker --network none
- **Report security issues** — See [SECURITY.md](SECURITY.md)

## Pull Request Checklist

- [ ] Tests pass: python -m pytest tests/ -v
- [ ] Linting passes: uff check .
- [ ] New features have tests
- [ ] No hardcoded secrets or API keys
- [ ] .env.example updated if new config keys added
- [ ] Documentation updated if behavior changes
- [ ] Type hints added to new functions
- [ ] Docstrings added to new classes and methods

## Reporting Issues

When filing a bug report, please include:

1. Python version (python --version)
2. Operating system
3. Steps to reproduce
4. Expected behavior
5. Actual behavior
6. Relevant log output
7. Your .env configuration (with secrets removed)
