"""Tests for cryptographic utilities."""

import os

import pytest

from flyinghoneysnitch.utils.crypto import (
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
        plain.write_text("Hello, FlyingHoneySnitch!")

        enc = str(tmp_path / "encrypted.bin")
        dec = str(tmp_path / "decrypted.txt")

        encrypt_file(str(plain), enc, "secret")
        decrypt_file(enc, dec, "secret")

        assert (tmp_path / "decrypted.txt").read_text() == "Hello, FlyingHoneySnitch!"

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
