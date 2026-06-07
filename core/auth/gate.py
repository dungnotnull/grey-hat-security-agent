"""Authorization gate enforcement.

Every active scan command must pass through this gate before execution.
The gate verifies:
1. Auth token Ed25519 signature is valid
2. Token has not expired (expiry_unix > current_time)
3. Target is in authorized domains/IP ranges
4. Requested scan type is in token scope array
5. Current time is within testing_window (if specified)
6. Token has not been revoked

If any check fails, raises AuthorizationError.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from core.auth.token import (
    AuthToken,
    AuthTokenManager,
    ScopeItem,
    TokenStatus,
)


class AuthorizationError(Exception):
    """Raised when authorization check fails.

    Includes specific reason for the failure for audit logging.
    """
    def __init__(self, reason: str, token_id: str = "", target: str = "", scan_type: str = ""):
        self.reason = reason
        self.token_id = token_id
        self.target = target
        self.scan_type = scan_type
        super().__init__(
            f"Authorization denied: {reason} "
            f"(token={token_id}, target={target}, scan_type={scan_type})"
        )


class AuthorizationGate:
    """Enforces authorization checks before any active scan.

    Usage:
        gate = AuthorizationGate()
        gate.authorize(token, target="example.com", scan_type=ScopeItem.PORT_SCAN)
    """

    def __init__(self, revoked_token_ids: Optional[set[str]] = None):
        """Initialize the authorization gate.

        Args:
            revoked_token_ids: Set of revoked token IDs. In production,
                this is loaded from the database.
        """
        self._revoked_token_ids = revoked_token_ids or set()

    def authorize(
        self,
        token: AuthToken,
        target: str,
        scan_type: ScopeItem,
        path: str = "/",
    ) -> AuthToken:
        """Full authorization check. Returns token if all checks pass.

        Args:
            token: The AuthToken to verify.
            target: Target domain or IP address to scan.
            scan_type: Type of scan being requested.
            path: URL path being scanned (for path exclusion check).

        Returns:
            The verified AuthToken.

        Raises:
            AuthorizationError: If any check fails, with specific reason.
        """
        # 1. Check token has signature
        if token.signature is None:
            raise AuthorizationError(
                reason="Token is unsigned — no Ed25519 signature present",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 2. Verify Ed25519 signature
        if not AuthTokenManager.verify_token(token):
            raise AuthorizationError(
                reason="Ed25519 signature verification failed — token may be forged or tampered",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 3. Check expiry
        if AuthTokenManager.is_expired(token):
            expiry_iso = datetime.fromtimestamp(token.expiry_unix, tz=timezone.utc).isoformat()
            raise AuthorizationError(
                reason=f"Token expired at {expiry_iso}",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 4. Check revocation
        if token.token_id in self._revoked_token_ids:
            raise AuthorizationError(
                reason="Token has been revoked",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 5. Check target authorization
        if not AuthTokenManager.is_target_authorized(token, target):
            raise AuthorizationError(
                reason=f"Target '{target}' not in authorized scope: domains={token.target.domains}, ip_ranges={token.target.ip_ranges}",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 6. Check target not in exclusions
        from core.auth.token import AuthTokenManager as mgr
        for excl in token.target.excluded:
            if target == excl or target.endswith("." + excl):
                raise AuthorizationError(
                    reason=f"Target '{target}' is explicitly excluded from scope",
                    token_id=token.token_id,
                    target=target,
                    scan_type=scan_type.value,
                )

        # 7. Check scan type in scope
        if not AuthTokenManager.is_in_scope(token, scan_type):
            raise AuthorizationError(
                reason=f"Scan type '{scan_type.value}' not in authorized scope: {[s.value for s in token.scope]}",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 8. Check testing window
        if not AuthTokenManager.is_within_testing_window(token):
            window = token.restrictions.testing_window if token.restrictions else None
            raise AuthorizationError(
                reason=f"Current time is outside permitted testing window ({window})",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 9. Check path exclusions
        if AuthTokenManager.is_path_excluded(token, path):
            raise AuthorizationError(
                reason=f"Path '{path}' is excluded from scanning",
                token_id=token.token_id,
                target=target,
                scan_type=scan_type.value,
            )

        # 10. Check exploitation restrictions
        if token.restrictions and token.restrictions.no_exploitation:
            if scan_type == ScopeItem.POC_SANDBOX:
                raise AuthorizationError(
                    reason="Token restricts exploitation — POC_SANDBOX not allowed",
                    token_id=token.token_id,
                    target=target,
                    scan_type=scan_type.value,
                )

        return token

    def revoke_token(self, token_id: str) -> None:
        """Revoke a token by its ID. Revoked tokens cannot be used."""
        self._revoked_token_ids.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        """Check if a token ID has been revoked."""
        return token_id in self._revoked_token_ids

    def check_status(self, token: AuthToken) -> TokenStatus:
        """Determine the current status of a token.

        Returns:
            TokenStatus: ACTIVE, EXPIRED, or REVOKED.
        """
        if token.token_id in self._revoked_token_ids:
            return TokenStatus.REVOKED
        if token.signature is None:
            return TokenStatus.CREATED
        if AuthTokenManager.is_expired(token):
            return TokenStatus.EXPIRED
        return TokenStatus.ACTIVE
