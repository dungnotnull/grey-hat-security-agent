"""Configuration module.

Provides:
- Settings: Pydantic-settings configuration class loaded from .env
"""

from config.settings import Settings, settings

__all__ = ["Settings", "settings"]
