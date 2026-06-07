"""Authorization token system.

Provides:
- AuthToken: Pydantic model for authorization tokens
- AuthTokenManager: Create, sign, verify, manage tokens
- ScopeItem: Enum of authorized scan types
- AuthorizationGate: Enforcement checks before scan execution
- AuthorizationError: Exception for authorization failures
"""

from core.auth.token import AuthToken, AuthTokenManager, ScopeItem, TokenStatus, TargetSpec, TestingWindow, Restrictions, Signature
from core.auth.gate import AuthorizationGate, AuthorizationError

__all__ = [
    "AuthToken",
    "AuthTokenManager",
    "ScopeItem",
    "TokenStatus",
    "TargetSpec",
    "TestingWindow",
    "Restrictions",
    "Signature",
    "AuthorizationGate",
    "AuthorizationError",
]
