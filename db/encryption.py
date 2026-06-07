"""AES-256-GCM application-layer encryption for SQLite storage.

Uses the cryptography library for:
- AES-256-GCM encryption of sensitive fields
- Ed25519 key generation, signing, verification
- Key derivation from master key in .env

Master key never stored in database; only in .env file.
All encryption/decryption happens at application layer.
"""

from __future__ import annotations

from utils.crypto import encrypt_field, decrypt_field


class FieldEncryptor:
    """Application-layer field encryption using AES-256-GCM.

    Usage:
        encryptor = FieldEncryptor(master_key=settings.encryption_key)
        encrypted = encryptor.encrypt("sensitive data")
        decrypted = encryptor.decrypt(encrypted)
    """

    def __init__(self, master_key: str):
        """Initialize with the master encryption key.

        Args:
            master_key: The master key from .env (used for key derivation).
        """
        if not master_key:
            raise ValueError("Encryption master key is required. Set ENCRYPTION_KEY in .env")
        self._master_key = master_key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string field.

        Args:
            plaintext: The plaintext string to encrypt.

        Returns:
            Base64-encoded string containing salt + nonce + ciphertext + tag.
        """
        return encrypt_field(plaintext, self._master_key)

    def decrypt(self, encrypted: str) -> str:
        """Decrypt an encrypted string field.

        Args:
            encrypted: Base64-encoded encrypted string.

        Returns:
            The original plaintext string.

        Raises:
            ValueError: If decryption fails (wrong key or corrupted data).
        """
        return decrypt_field(encrypted, self._master_key)

    def encrypt_dict(self, data: dict) -> str:
        """Encrypt a dictionary by serializing to JSON first.

        Args:
            data: Dictionary to encrypt.

        Returns:
            Encrypted JSON string.
        """
        import json
        return self.encrypt(json.dumps(data))

    def decrypt_dict(self, encrypted: str) -> dict:
        """Decrypt and deserialize a JSON dictionary.

        Args:
            encrypted: Encrypted JSON string.

        Returns:
            Original dictionary.
        """
        import json
        return json.loads(self.decrypt(encrypted))

    def encrypt_list(self, data: list) -> str:
        """Encrypt a list by serializing to JSON first."""
        import json
        return self.encrypt(json.dumps(data))

    def decrypt_list(self, encrypted: str) -> list:
        """Decrypt and deserialize a JSON list."""
        import json
        return json.loads(self.decrypt(encrypted))
