"""Utility modules.

Provides:
- Crypto: Ed25519 signing, AES-256-GCM encryption, SHA-256 hashing
- Helpers: Rate limiting, retry logic, domain validation, IP parsing
"""

from utils.crypto import (
    generate_ed25519_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    sign_payload,
    verify_signature,
    encrypt_field,
    decrypt_field,
    canonical_json,
    sha256_hash,
    hash_token_payload,
    generate_uuid,
    utc_now_unix,
)
from utils.helpers import (
    TokenBucketRateLimiter,
    retry_with_backoff,
    is_valid_domain,
    is_valid_ip,
    is_valid_cidr,
    expand_cidr,
    ip_in_range,
    format_timestamp,
    parse_iso_timestamp,
    iso_now,
)

__all__ = [
    "generate_ed25519_keypair",
    "serialize_private_key",
    "serialize_public_key",
    "load_private_key",
    "load_public_key",
    "sign_payload",
    "verify_signature",
    "encrypt_field",
    "decrypt_field",
    "canonical_json",
    "sha256_hash",
    "hash_token_payload",
    "generate_uuid",
    "utc_now_unix",
    "TokenBucketRateLimiter",
    "retry_with_backoff",
    "is_valid_domain",
    "is_valid_ip",
    "is_valid_cidr",
    "expand_cidr",
    "ip_in_range",
    "format_timestamp",
    "parse_iso_timestamp",
    "iso_now",
]
