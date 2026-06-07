"""Database models and encryption.

Provides:
- SQLAlchemy models: Target, Finding, AuthTokenRecord, DomainIntel, AuditLog, LLMCache, CVEMirror, MITRETechnique, Scan
- FieldEncryptor: AES-256-GCM field encryption
- Async session management
"""

from db.models import (
    Base, Target, Finding, AuthTokenRecord, DomainIntel,
    AuditLog, LLMCache, CVEMirror, MITRETechnique, Scan,
)
from db.encryption import FieldEncryptor
from db.session import get_session, get_sync_session, init_db, close_db

__all__ = [
    "Base",
    "Target",
    "Finding",
    "AuthTokenRecord",
    "DomainIntel",
    "AuditLog",
    "LLMCache",
    "CVEMirror",
    "MITRETechnique",
    "Scan",
    "FieldEncryptor",
    "get_session",
    "get_sync_session",
    "init_db",
    "close_db",
]
