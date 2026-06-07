"""Cryptographic utilities for the grey-hat-security-agent.

Provides:
- Ed25519 key generation, signing, and verification
- AES-256-GCM encryption/decryption for database fields
- SHA-256 hashing for audit trails
- Canonical JSON serialization for token signing
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, InvalidTag


# ---------------------------------------------------------------------------
# Ed25519 Key Management
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 keypair for token signing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(
    private_key: ed25519.Ed25519PrivateKey,
    passphrase: Optional[str] = None,
) -> str:
    """Serialize Ed25519 private key to PEM format (optionally encrypted)."""
    if passphrase:
        enc_alg = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc_alg = serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )
    return pem.decode("utf-8")


def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> str:
    """Serialize Ed25519 public key to PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def load_private_key(pem_data: str, passphrase: Optional[str] = None) -> ed25519.Ed25519PrivateKey:
    """Load Ed25519 private key from PEM data."""
    return serialization.load_pem_private_key(
        pem_data.encode(),
        password=passphrase.encode() if passphrase else None,
    )


def load_public_key(pem_data: str) -> ed25519.Ed25519PublicKey:
    """Load Ed25519 public key from PEM data."""
    return serialization.load_pem_public_key(pem_data.encode())


def sign_payload(private_key: ed25519.Ed25519PrivateKey, payload: bytes) -> str:
    """Sign a payload with Ed25519 private key. Returns base64-encoded signature."""
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature_b64: str,
    payload: bytes,
) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, payload)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def canonical_json(data: dict) -> bytes:
    """Serialize dict to canonical JSON bytes for deterministic signing.
    
    Rules:
    - Keys sorted lexicographically
    - No whitespace (separators=(',', ':'))
    - UTF-8 encoding
    - No trailing commas
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# SHA-256 Hashing (for audit trails)
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data. Returns hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_token_payload(payload: dict) -> str:
    """Compute SHA-256 hash of canonical JSON payload. Returns hex string."""
    canonical = canonical_json(payload)
    return sha256_hash(canonical)


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption
# ---------------------------------------------------------------------------

def _derive_key(master_key: str, salt: bytes) -> bytes:
    """Derive 256-bit key from master key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(master_key.encode())


def encrypt_field(plaintext: str, master_key: str) -> str:
    """Encrypt a string field with AES-256-GCM.
    
    Returns base64-encoded string: salt(16) + nonce(12) + ciphertext + tag.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # ciphertext includes the tag (last 16 bytes) by default
    return base64.b64encode(salt + nonce + ciphertext).decode("utf-8")


def decrypt_field(encrypted: str, master_key: str) -> str:
    """Decrypt an AES-256-GCM encrypted field.
    
    Input: base64-encoded string: salt(16) + nonce(12) + ciphertext + tag.
    """
    try:
        raw = base64.b64decode(encrypted)
        salt = raw[:16]
        nonce = raw[16:28]
        ciphertext = raw[28:]
        key = _derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except (InvalidTag, Exception) as e:
        raise ValueError(f"Decryption failed: {e}") from e


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def generate_uuid() -> str:
    """Generate a UUID v4 string."""
    import uuid
    return str(uuid.uuid4())


def utc_now_unix() -> int:
    """Return current UTC time as Unix timestamp."""
    return int(datetime.now(timezone.utc).timestamp())
