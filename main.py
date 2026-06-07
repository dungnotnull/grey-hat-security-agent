"""grey-hat-security-agent main entry point.

Authorized Cybersecurity Research & Red-Team Intelligence Agent.

Usage:
    python main.py intel score <domain>
    python main.py scan --target <host> --token-file <path>
    python main.py report generate --scan-id <id>
    python main.py authorize create --target example.com
    python main.py update --source all
    python main.py db-init
"""

from cli.main import app

if __name__ == "__main__":
    app()
