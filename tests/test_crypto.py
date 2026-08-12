"""Tests for cryptographic utilities."""

import os

import pytest

from honeysnatch.utils.crypto import (
    MAGIC,
    derive_key,
    encrypt_file,
    decrypt_file,
    get_or_create_hmac_key,
    hmac_sha256,
    is_encrypted_file,
)


class TestDeriveKey:

    def test_deterministic(self):
        salt = b"\x00" * 16
        k1 = derive_key("password", salt)
        k2 = derive_key("password", salt)
        assert k1 == k2

    def test_different_salt(self):
        k1 = derive_key("password", b"\x00" * 16)
        k2 = derive_key("password", b"\x01" * 16)
        assert k1 != k2

    def test_key_length(self):
        key = derive_key("test", os.urandom(16))
        assert len(key) == 32


class TestFileEncryption:

    def test_roundtrip(self, tmp_path):
        plain = tmp_path / "plain.txt"
        plain.write_text("Hello, honeysnatch!")

        enc = str(tmp_path / "encrypted.bin")
        dec = str(tmp_path / "decrypted.txt")

        encrypt_file(str(plain), enc, "secret")
        decrypt_file(enc, dec, "secret")

        assert (tmp_path / "decrypted.txt").read_text() == "Hello, honeysnatch!"

    def test_encrypted_file_has_magic(self, tmp_path):
        plain = tmp_path / "data.bin"
        plain.write_bytes(b"test data")
        enc = str(tmp_path / "enc.bin")

        encrypt_file(str(plain), enc, "pass")

        with open(enc, "rb") as f:
            assert f.read(4) == MAGIC

    def test_is_encrypted_file(self, tmp_path):
        plain = tmp_path / "plain.txt"
        plain.write_text("not encrypted")

        enc = str(tmp_path / "enc.bin")
        encrypt_file(str(plain), enc, "pass")

        assert is_encrypted_file(enc)
        assert not is_encrypted_file(str(plain))

    def test_not_encrypted_file_check(self, tmp_path):
        f = tmp_path / "normal.txt"
        f.write_text("just text")
        assert not is_encrypted_file(str(f))

    def test_nonexistent_file(self):
        assert not is_encrypted_file("/nonexistent/path")

    def test_invalid_magic_raises(self, tmp_path):
        fake = tmp_path / "fake.enc"
        fake.write_bytes(b"FAKE" + b"\x00" * 100)
        with pytest.raises(ValueError, match="Not a valid FHS encrypted file"):
            decrypt_file(str(fake), str(tmp_path / "out"), "pass")


class TestHmac:

    def test_hmac_deterministic(self):
        key = b"\x00" * 32
        h1 = hmac_sha256(key, b"test")
        h2 = hmac_sha256(key, b"test")
        assert h1 == h2

    def test_hmac_different_data(self):
        key = b"\x00" * 32
        h1 = hmac_sha256(key, b"test1")
        h2 = hmac_sha256(key, b"test2")
        assert h1 != h2

    def test_hmac_hex_length(self):
        h = hmac_sha256(b"\x00" * 32, b"data")
        assert len(h) == 64  # SHA256 hex digest


class TestHmacKey:

    def test_create_new_key(self, tmp_path):
        key_path = str(tmp_path / "hmac.key")
        key = get_or_create_hmac_key(key_path)
        assert len(key) == 32

    def test_load_existing_key(self, tmp_path):
        key_path = str(tmp_path / "hmac.key")
        k1 = get_or_create_hmac_key(key_path)
        k2 = get_or_create_hmac_key(key_path)
        assert k1 == k2

    def test_key_persists(self, tmp_path):
        key_path = str(tmp_path / "subdir" / "hmac.key")
        key = get_or_create_hmac_key(key_path)
        assert os.path.exists(key_path)
        loaded = bytes.fromhex(open(key_path).read().strip())
        assert loaded == key


class TestHmacKeyPermissions:
    """Review findings F-05, F-06, F-08."""

    def test_new_key_has_0600_from_start_no_race(self, tmp_path):
        """F-05: no world-readable window between create and chmod."""
        import stat
        if os.name == "nt":
            pytest.skip("POSIX perm check")
        key_path = tmp_path / "hmac.key"
        get_or_create_hmac_key(str(key_path))
        mode = stat.S_IMODE(key_path.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_symlink_at_key_path_is_refused(self, tmp_path):
        """F-06: pre-existing symlink at key_path must NOT get the fresh key."""
        if os.name == "nt":
            pytest.skip("POSIX symlink")
        victim = tmp_path / "attacker-owned.txt"
        victim.write_text("original")
        key_path = tmp_path / "hmac.key"
        os.symlink(str(victim), str(key_path))

        # Should refuse to follow the symlink; nothing gets written to victim.
        with pytest.raises(OSError):
            get_or_create_hmac_key(str(key_path))
        assert victim.read_text() == "original", \
            "F-06 regression: key was written through a symlink"


class TestEncryptedHeaderAuthenticated:
    """Review finding F-07: header (MAGIC + salt + nonce) must be AAD."""

    def test_header_tamper_fails_decrypt(self, tmp_path):
        from cryptography.exceptions import InvalidTag
        from honeysnatch.utils.crypto import decrypt_file, encrypt_file

        src = tmp_path / "plain.txt"
        enc = tmp_path / "enc.fhs"
        dst = tmp_path / "out.txt"
        src.write_bytes(b"secret data")

        encrypt_file(str(src), str(enc), "correct horse battery staple")

        # Corrupt one byte of the salt (offset 4..20). Nothing else changes.
        raw = bytearray(enc.read_bytes())
        raw[4] ^= 0x01
        enc.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            decrypt_file(str(enc), str(dst), "correct horse battery staple")

    def test_valid_roundtrip_still_works(self, tmp_path):
        from honeysnatch.utils.crypto import decrypt_file, encrypt_file

        src = tmp_path / "p.txt"
        enc = tmp_path / "e.fhs"
        dst = tmp_path / "o.txt"
        payload = b"the quick brown fox\x00\xff\n" * 100
        src.write_bytes(payload)

        encrypt_file(str(src), str(enc), "pw")
        decrypt_file(str(enc), str(dst), "pw")
        assert dst.read_bytes() == payload


class TestIsEncryptedFileTristate:
    """Review finding F-13: distinguish 'not encrypted' from 'cannot read'."""

    def test_encrypted_returns_true(self, tmp_path):
        from honeysnatch.utils.crypto import encrypt_file, is_encrypted_file
        src = tmp_path / "p"; src.write_bytes(b"x")
        enc = tmp_path / "e"
        encrypt_file(str(src), str(enc), "pw")
        assert is_encrypted_file(str(enc)) is True

    def test_plaintext_returns_false(self, tmp_path):
        from honeysnatch.utils.crypto import is_encrypted_file
        p = tmp_path / "plain"; p.write_bytes(b"hello")
        assert is_encrypted_file(str(p)) is False

    def test_unreadable_returns_none(self, tmp_path):
        from honeysnatch.utils.crypto import is_encrypted_file
        # File does not exist — indistinguishable from permission denied
        # at this API level, both are "cannot read".
        assert is_encrypted_file(str(tmp_path / "missing")) is None
