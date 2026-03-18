"""Cryptographic utilities for honeysnatch.

Provides file encryption/decryption using AES-256-GCM with
PBKDF2-derived keys for secure data export and storage.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from honeysnatch.utils.logger import get_logger

log = get_logger("crypto")

# PBKDF2 iterations (OWASP 2024 recommendation for HMAC-SHA256)
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

# File header magic bytes to identify encrypted files
MAGIC = b"FHS\x01"  # honeysnatch v1 encrypted format


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key from a passphrase using PBKDF2.

    Args:
        passphrase: User-provided passphrase.
        salt: Random salt (16 bytes).

    Returns:
        32-byte derived key.
    """
    from hashlib import pbkdf2_hmac

    return pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Encrypt a file using AES-256-GCM.

    File format: MAGIC(4) + salt(16) + nonce(12) + ciphertext + tag(16)

    Args:
        input_path: Path to plaintext file.
        output_path: Path to write encrypted file.
        passphrase: Encryption passphrase.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plaintext = Path(input_path).read_bytes()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes tag

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    log.info("Encrypted %s -> %s (%d bytes)", input_path, output_path, len(ciphertext))


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Decrypt an AES-256-GCM encrypted file.

    Args:
        input_path: Path to encrypted file.
        output_path: Path to write decrypted file.
        passphrase: Decryption passphrase.

    Raises:
        ValueError: If file is not a valid FHS encrypted file.
        cryptography.exceptions.InvalidTag: If passphrase is wrong.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = Path(input_path).read_bytes()

    if data[:4] != MAGIC:
        raise ValueError("Not a valid FHS encrypted file")

    offset = 4
    salt = data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    Path(output_path).write_bytes(plaintext)
    log.info("Decrypted %s -> %s", input_path, output_path)


def is_encrypted_file(path: str) -> bool:
    """Check if a file is FHS-encrypted by reading its magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except (OSError, IOError):
        return False


def hmac_sha256(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 and return hex digest.

    Used by the audit logger for hash chaining.
    """
    import hmac
    import hashlib

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def get_or_create_hmac_key(key_path: str) -> bytes:
    """Load or generate a persistent HMAC key for audit log chaining.

    Args:
        key_path: Path to the key file.

    Returns:
        32-byte HMAC key.
    """
    path = Path(key_path)
    if path.exists():
        return bytes.fromhex(path.read_text().strip())

    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex())
    # Restrict permissions on Unix
    try:
        path.chmod(0o600)
    except OSError:
        pass  # Windows doesn't support Unix permissions
    log.info("Generated new HMAC key: %s", key_path)
    return key
