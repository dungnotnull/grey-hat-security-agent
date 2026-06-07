"""Authorization token model, signing, verification, and lifecycle management.

Implements the AuthToken system using Ed25519 signatures as specified
in docs/AUTH-TOKEN-SCHEMA.md. Every active scan requires a valid, signed
AuthToken stored in the encrypted SQLite database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from utils.crypto import (
    canonical_json,
    generate_uuid,
    generate_ed25519_keypair,
    sign_payload,
    verify_signature,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    hash_token_payload,
    utc_now_unix,
    encrypt_field,
    decrypt_field,
)
from utils.helpers import is_valid_domain, is_valid_cidr


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScopeItem(str, Enum):
    """Authorized assessment activity types."""
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    SSL_TLS_CHECK = "ssl_tls_check"
    WEB_CRAWLER = "web_crawler"
    WEB_PASSIVE_SCAN = "web_passive_scan"
    WEB_ACTIVE_SCAN = "web_active_scan"
    DIRECTORY_FUZZ = "directory_fuzz"
    PARAMETER_FUZZ = "parameter_fuzz"
    CVE_LOOKUP = "cve_lookup"
    SOURCE_CODE_SCAN = "source_code_scan"
    DNS_ENUM = "dns_enum"
    POC_SANDBOX = "poc_sandbox"


class TokenStatus(str, Enum):
    """Authorization token lifecycle statuses."""
    CREATED = "created"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ARCHIVED = "archived"


# ---------------------------------------------------------------------------
# Nested Models
# ---------------------------------------------------------------------------

class TargetSpec(BaseModel):
    """Authorized target systems specification."""
    domains: list[str] = Field(..., min_length=1, description="List of authorized domain names")
    ip_ranges: list[str] = Field(default_factory=list, description="CIDR ranges of authorized IPs")
    excluded: list[str] = Field(default_factory=list, description="Explicitly excluded subdomains/IPs")

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        for d in v:
            if not is_valid_domain(d):
                raise ValueError(f"Invalid domain: {d}")
        return v

    @field_validator("ip_ranges")
    @classmethod
    def validate_ip_ranges(cls, v: list[str]) -> list[str]:
        for cidr in v:
            if not is_valid_cidr(cidr):
                raise ValueError(f"Invalid CIDR: {cidr}")
        return v


class TestingWindow(BaseModel):
    """Permitted testing time window."""
    start_utc: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$", description="HH:MM UTC")
    end_utc: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$", description="HH:MM UTC")
    days: list[str] = Field(default_factory=lambda: ["mon", "tue", "wed", "thu", "fri"])


class Restrictions(BaseModel):
    """Optional restrictions on testing parameters."""
    max_concurrent_requests: int = Field(default=10, ge=1, le=100)
    requests_per_second: int = Field(default=5, ge=1, le=50)
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_ip_ranges: list[str] = Field(default_factory=list)
    testing_window: Optional[TestingWindow] = None
    no_exploitation: bool = Field(default=True)
    no_dos: bool = Field(default=True)


class Signature(BaseModel):
    """Ed25519 signature over the token payload."""
    algorithm: str = Field(default="Ed25519")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    signature_bytes: str = Field(..., description="Base64-encoded Ed25519 signature")
    signed_at_unix: int = Field(default_factory=utc_now_unix)


# ---------------------------------------------------------------------------
# AuthToken Model
# ---------------------------------------------------------------------------

class AuthToken(BaseModel):
    """Authorization token for active security assessments.

    Every active scan command MUST present a valid AuthToken that passes
    all verification checks in the authorization gate.
    """
    version: str = Field(default="1.0")
    token_id: str = Field(default_factory=generate_uuid)
    target: TargetSpec
    scope: list[ScopeItem] = Field(..., min_length=1)
    expiry_unix: int = Field(..., description="Unix timestamp when token expires")
    issued_at_unix: int = Field(default_factory=utc_now_unix)
    approver_name: str = Field(..., min_length=2, max_length=200)
    approver_role: Optional[str] = None
    approver_contact: Optional[str] = None
    operator_name: str = Field(..., min_length=2, max_length=200)
    operator_contact: Optional[str] = None
    authorization_document: Optional[str] = None
    restrictions: Optional[Restrictions] = None
    notes: Optional[str] = None
    signature: Optional[Signature] = None


class AuthTokenManager:
    """Manager for creating, signing, verifying, and managing AuthTokens."""

    @staticmethod
    def create_unsigned(
        target_domains: list[str],
        target_ip_ranges: list[str] | None = None,
        scope: list[ScopeItem] | None = None,
        approver_name: str = "Unknown",
        operator_name: str = "Unknown",
        expiry_hours: int = 168,
        excluded: list[str] | None = None,
        restrictions: Restrictions | None = None,
        notes: str | None = None,
    ) -> AuthToken:
        """Create an unsigned AuthToken.

        Args:
            target_domains: List of authorized domain names.
            target_ip_ranges: Optional CIDR ranges.
            scope: List of authorized scan types.
            approver_name: Name of the person authorizing the test.
            operator_name: Name of the person conducting the test.
            expiry_hours: Hours until token expires (default 168 = 1 week).
            excluded: Explicitly excluded subdomains/IPs.
            restrictions: Optional testing restrictions.
            notes: Free-form notes.

        Returns:
            Unsigned AuthToken (signature=None).
        """
        if scope is None:
            scope = [ScopeItem.PORT_SCAN, ScopeItem.SERVICE_DETECTION, ScopeItem.CVE_LOOKUP]

        target = TargetSpec(
            domains=target_domains,
            ip_ranges=target_ip_ranges or [],
            excluded=excluded or [],
        )

        now = utc_now_unix()
        token = AuthToken(
            target=target,
            scope=scope,
            expiry_unix=now + expiry_hours * 3600,
            issued_at_unix=now,
            approver_name=approver_name,
            operator_name=operator_name,
            restrictions=restrictions,
            notes=notes,
        )
        return token

    @staticmethod
    def sign_token(token: AuthToken, private_key_pem: str, passphrase: str | None = None) -> AuthToken:
        """Sign an AuthToken with an Ed25519 private key.

        Args:
            token: Unsigned AuthToken.
            private_key_pem: PEM-encoded Ed25519 private key.
            passphrase: Optional passphrase for encrypted private key.

        Returns:
            AuthToken with signature field populated.
        """
        private_key = load_private_key(private_key_pem, passphrase)
        public_key = private_key.public_key()

        # Get canonical payload (all fields except signature)
        payload_dict = token.model_dump(exclude={"signature"})
        payload_bytes = canonical_json(payload_dict)

        signature_b64 = sign_payload(private_key, payload_bytes)
        public_key_b64 = serialize_public_key(public_key)

        token.signature = Signature(
            algorithm="Ed25519",
            public_key=public_key_b64,
            signature_bytes=signature_b64,
            signed_at_unix=utc_now_unix(),
        )
        return token

    @staticmethod
    def verify_token(token: AuthToken) -> bool:
        """Verify the Ed25519 signature on an AuthToken.

        Args:
            token: Signed AuthToken.

        Returns:
            True if signature is valid, False otherwise.
        """
        if token.signature is None:
            return False

        try:
            public_key = load_public_key(token.signature.public_key)
        except Exception:
            return False

        payload_dict = token.model_dump(exclude={"signature"})
        payload_bytes = canonical_json(payload_dict)

        return verify_signature(
            public_key,
            token.signature.signature_bytes,
            payload_bytes,
        )

    @staticmethod
    def is_expired(token: AuthToken) -> bool:
        """Check if token has expired."""
        return utc_now_unix() > token.expiry_unix

    @staticmethod
    def is_in_scope(token: AuthToken, scan_type: ScopeItem) -> bool:
        """Check if a scan type is within the token's scope."""
        return scan_type in token.scope

    @staticmethod
    def is_target_authorized(token: AuthToken, target_host: str) -> bool:
        """Check if a target host is authorized by the token.

        Args:
            token: AuthToken with target specification.
            target_host: Domain name or IP address to check.

        Returns:
            True if target is authorized.
        """
        from utils.helpers import is_valid_domain, is_valid_ip, ip_in_range

        # Check exclusions first
        for excl in token.target.excluded:
            if target_host == excl or target_host.endswith("." + excl):
                return False
            try:
                if ip_in_range(target_host, [excl]):
                    return False
            except Exception:
                pass

        # Check domains
        if is_valid_domain(target_host):
            for domain in token.target.domains:
                if target_host == domain or target_host.endswith("." + domain):
                    return True

        # Check IP ranges
        if is_valid_ip(target_host) and token.target.ip_ranges:
            return ip_in_range(target_host, token.target.ip_ranges)

        # If no IP ranges specified and domain didn't match, deny
        return bool(token.target.ip_ranges) and ip_in_range(target_host, token.target.ip_ranges) if is_valid_ip(target_host) else False

    @staticmethod
    def is_within_testing_window(token: AuthToken) -> bool:
        """Check if current time is within the token's testing window.

        Returns True if no testing window is specified (no restriction).
        """
        if token.restrictions is None or token.restrictions.testing_window is None:
            return True

        window = token.restrictions.testing_window
        now = datetime.now(timezone.utc)

        # Check day of week
        day_map = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
        if day_map.get(now.strftime("%a").lower()[:3], -1) not in [day_map.get(d, -1) for d in window.days]:
            return False

        # Check time window
        now_minutes = now.hour * 60 + now.minute
        start_parts = window.start_utc.split(":")
        end_parts = window.end_utc.split(":")
        start_minutes = int(start_parts[0]) * 60 + int(start_parts[1])
        end_minutes = int(end_parts[0]) * 60 + int(end_parts[1])

        if start_minutes <= end_minutes:
            return start_minutes <= now_minutes <= end_minutes
        else:
            # Overnight window
            return now_minutes >= start_minutes or now_minutes <= end_minutes

    @staticmethod
    def is_path_excluded(token: AuthToken, path: str) -> bool:
        """Check if a URL path is excluded from scanning."""
        if token.restrictions is None:
            return False
        for excluded in token.restrictions.excluded_paths:
            if path.startswith(excluded):
                return True
        return False

    @staticmethod
    def get_token_hash(token: AuthToken) -> str:
        """Compute SHA-256 hash of the token payload for audit logging."""
        payload_dict = token.model_dump(exclude={"signature"})
        return hash_token_payload(payload_dict)

    @staticmethod
    def create_keypair(passphrase: str | None = None) -> dict:
        """Generate a new Ed25519 keypair for token signing.

        Args:
            passphrase: Optional passphrase to encrypt the private key.

        Returns:
            Dict with key_id, private_key_pem, public_key_pem.
        """
        private_key, public_key = generate_ed25519_keypair()
        key_id = generate_uuid()
        return {
            "key_id": key_id,
            "private_key_pem": serialize_private_key(private_key, passphrase),
            "public_key_pem": serialize_public_key(public_key),
        }
