"""Cryptographic utilities for honeysnatch.

Provides file encryption/decryption using AES-256-GCM with
PBKDF2-derived keys for secure data export and storage.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional

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

    F-07 remediation: MAGIC + salt + nonce are passed as associated_data,
    so any tampering with the header (magic-byte strip, salt swap, nonce
    swap) invalidates the GCM tag on decrypt.

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

    header = MAGIC + salt + nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, header)  # includes tag

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(ciphertext)

    log.info("Encrypted %s -> %s (%d bytes)", input_path, output_path, len(ciphertext))


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Decrypt an AES-256-GCM encrypted file.

    Header (MAGIC + salt + nonce) is bound via GCM associated_data — see
    F-07 note in encrypt_file. Files written by the pre-F-07 code path
    (header not authenticated) will fail here with InvalidTag; this is
    the correct behavior for tamper-evidence.

    Args:
        input_path: Path to encrypted file.
        output_path: Path to write decrypted file.
        passphrase: Decryption passphrase.

    Raises:
        ValueError: If file is not a valid FHS encrypted file.
        cryptography.exceptions.InvalidTag: If passphrase is wrong OR
            the header has been tampered with.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = Path(input_path).read_bytes()

    if data[:4] != MAGIC:
        raise ValueError("Not a valid FHS encrypted file")

    header_len = 4 + SALT_SIZE + NONCE_SIZE
    header = data[:header_len]
    salt = data[4:4 + SALT_SIZE]
    nonce = data[4 + SALT_SIZE:header_len]
    ciphertext = data[header_len:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, header)

    Path(output_path).write_bytes(plaintext)
    log.info("Decrypted %s -> %s", input_path, output_path)


def is_encrypted_file(path: str) -> Optional[bool]:
    """Return True/False if the magic bytes could be read, None on I/O error.

    F-13 remediation: previously returned False for both "not encrypted"
    and "cannot read" — callers acting on the result could be misled by
    a permission-denied file.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except (OSError, IOError):
        return None


def hmac_sha256(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 and return hex digest.

    Used by the audit logger for hash chaining.
    """
    import hmac
    import hashlib

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def get_or_create_hmac_key(key_path: str) -> bytes:
    """Load or generate a persistent HMAC key for audit log chaining.

    F-05 remediation: the key file is created with mode 0600 from the
    first write — no world-readable window between write() and chmod().
    F-06 remediation: O_NOFOLLOW refuses to follow a pre-existing
    symlink at key_path, defeating the symlink-swap attack against the
    parent directory.
    F-08 remediation: Windows can't apply POSIX permissions through
    O_NOFOLLOW/mode, so on Windows we fall back to a normal write and
    log a WARNING (not a silent pass) telling the operator to lock the
    file down via NTFS ACLs.

    Args:
        key_path: Path to the key file.

    Returns:
        32-byte HMAC key.
    """
    path = Path(key_path)
    # F-06: reject any symlink at the key path outright. On the read
    # side (path already exists) a symlink is either the operator's
    # earlier install (in which case we still refuse — a symlinked key
    # is not a supported configuration) or an attacker's setup.
    if path.is_symlink():
        raise OSError(
            f"Refusing to use {key_path}: it is a symlink. Move the real "
            "key file to that location or choose a different path."
        )
    if path.exists():
        return bytes.fromhex(path.read_text().strip())

    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        # Windows: no O_NOFOLLOW, no chmod-to-0600. Write the file, log
        # a loud warning so the operator knows to apply an ACL.
        path.write_text(key.hex())
        log.warning(
            "HMAC key written to %s WITHOUT Unix permission enforcement. "
            "Restrict access via NTFS ACLs, e.g. `icacls %s /inheritance:r "
            "/grant:r %%USERNAME%%:F`", path, path,
        )
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(path), flags, 0o600)
        except FileExistsError:
            # A racing process created the file first — re-read it.
            return bytes.fromhex(path.read_text().strip())
        try:
            os.write(fd, key.hex().encode("ascii"))
        finally:
            os.close(fd)

    log.info("Generated new HMAC key: %s", key_path)
    return key
