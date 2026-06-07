"""Test configuration settings including new fields."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import Settings, configure_logging, check_environment


def test_settings_imports():
    """Verify that config.settings module can be imported."""
    from config import settings
    assert settings is not None


def test_settings_has_required_attributes():
    """Verify that Settings class has all required attributes."""
    s = Settings()
    assert hasattr(s, 'llm_provider')
    assert hasattr(s, 'claude_api_key')
    assert hasattr(s, 'openai_api_key')
    assert hasattr(s, 'ollama_base_url')
    assert hasattr(s, 'virustotal_api_key')
    assert hasattr(s, 'shodan_api_key')
    assert hasattr(s, 'nvd_api_key')
    assert hasattr(s, 'db_path')
    assert hasattr(s, 'encryption_key')
    assert hasattr(s, 'nmap_path')
    assert hasattr(s, 'zap_api_url')
    assert hasattr(s, 'zap_api_key')
    assert hasattr(s, 'phishtank_api_key')
    assert hasattr(s, 'google_safe_browsing_api_key')
    assert hasattr(s, 'report_output_dir')
    assert hasattr(s, 'knowledge_update_cron')
    assert hasattr(s, 'cors_allowed_origins')
    assert hasattr(s, 'log_level')


def test_settings_defaults():
    """Verify that Settings has correct default values."""
    s = Settings()
    assert s.llm_provider == "claude"
    assert s.ollama_base_url == "http://localhost:11434"
    assert s.db_path == "data/grey_hat_agent.db"
    assert s.nmap_path == "nmap"
    assert s.zap_api_url == "http://localhost:8090"
    assert s.zap_api_key == ""
    assert s.report_output_dir == "data/reports"
    assert s.knowledge_update_cron == "0 2 * * 0"
    assert s.cors_allowed_origins == "*"
    assert s.log_level == "INFO"


def test_configure_logging():
    """Verify configure_logging doesn't raise."""
    configure_logging()


def test_check_environment():
    """Verify check_environment returns a list."""
    warnings = check_environment()
    assert isinstance(warnings, list)
