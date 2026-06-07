"""Application configuration using pydantic-settings.

Loads configuration from environment variables and .env file.
All API keys loaded from environment; never hardcoded.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Do NOT use extra="ignore" - let typos raise errors
    )

    # LLM Provider Configuration
    llm_provider: str = "claude"  # claude | openai | ollama

    # API Keys (never logged or stored in DB)
    claude_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None

    # Ollama Configuration
    ollama_base_url: str = "http://localhost:11434"

    # VirusTotal
    virustotal_api_key: Optional[str] = None

    # Shodan
    shodan_api_key: Optional[str] = None

    # NVD
    nvd_api_key: Optional[str] = None

    # PhishTank
    phishtank_api_key: Optional[str] = None

    # Google Safe Browsing
    google_safe_browsing_api_key: Optional[str] = None

    # Database
    db_path: str = "data/grey_hat_agent.db"
    encryption_key: Optional[str] = None

    # Scanning
    nmap_path: str = "nmap"
    zap_api_url: str = "http://localhost:8090"
    zap_api_key: str = ""

    # Reporting
    report_output_dir: str = "data/reports"

    # Knowledge base
    knowledge_last_run_file: str = "data/knowledge_last_run.txt"

    # Logging
    log_level: str = "INFO"

    # Rate limiting (requests per minute)
    rate_limit_virustotal: int = 4
    rate_limit_shodan: int = 60
    rate_limit_nvd: int = 100

    # Risk score weights (must sum to 1.0)
    risk_weight_vt: float = 0.30
    risk_weight_feeds: float = 0.20
    risk_weight_nlp: float = 0.25
    risk_weight_age: float = 0.15
    risk_weight_whois: float = 0.10

    # APScheduler
    knowledge_update_cron: str = "0 2 * * 0"  # Sunday 02:00 UTC

    # CORS
    cors_allowed_origins: str = "*"  # Comma-separated origins, or "*" for dev


settings = Settings()


def configure_logging():
    """Configure application-wide logging based on settings."""
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("transformers").setLevel(logging.WARNING)
    logging.getLogger("torch").setLevel(logging.WARNING)


def check_environment():
    """Check for common configuration issues and warn the user."""
    warnings = []

    # Check if .env exists
    env_path = Path(".env")
    if not env_path.exists():
        warnings.append(
            "No .env file found. Copy .env.example to .env and configure your API keys."
        )

    # Check if encryption key is set
    if not settings.encryption_key:
        warnings.append(
            "ENCRYPTION_KEY not set. Database encryption will not work. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )

    # Check if any LLM provider is configured
    if not settings.claude_api_key and not settings.openai_api_key:
        if settings.llm_provider in ("claude", "openai"):
            warnings.append(
                f"LLM_PROVIDER is '{settings.llm_provider}' but no API key is set. "
                "Set CLAUDE_API_KEY or OPENAI_API_KEY in .env, or set LLM_PROVIDER=ollama for local LLM."
            )

    # Check critical directories
    for dir_path in [Path("data"), Path("data/cve_mirror"), Path("data/model_cache"), Path("data/reports")]:
        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created directory: {dir_path}")
            except OSError as e:
                warnings.append(f"Cannot create directory {dir_path}: {e}")

    for warning in warnings:
        logger.warning("WARNING: %s", warning)

    return warnings
