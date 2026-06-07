"""FastAPI REST API for grey-hat-security-agent.

Provides endpoints for auth, intel, scan, report, analysis, and knowledge.
"""

from api.main import app

__all__ = ["app"]
