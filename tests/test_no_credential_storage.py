"""Proof-carrying test for the SECURITY.md 'no credential storage' claim.

SECURITY.md states: 'The tool never stores WiFi passwords or authentication
credentials.' That's a policy assertion — this test is the technical
enforcement (review finding F-17). It walks:

  1. Every SQLAlchemy Column on every schema record class.
  2. Every dataclass field on every core model.
  3. Every default config file shipped in `data/`.

and asserts no field/key name contains any of the forbidden credential
tokens: psk, password, passphrase, wpa_key, pmk, secret, credential.

If we ever ADD a legitimate reason to store one — e.g. an operator-
supplied passphrase for encrypted export — the exception belongs in the
ALLOWED_EXCEPTIONS list below with a clear justification, not as a
silent schema addition. That's the whole point of a proof-carrying test.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest


FORBIDDEN = re.compile(
    r"\b(psk|password|passphrase|wpa[_-]?key|pmk|secret|credential)\b",
    re.IGNORECASE,
)

# Fields/keys that legitimately match the forbidden regex but do NOT
# store captured credentials. Each entry needs a justification comment.
ALLOWED_EXCEPTIONS: set[str] = {
    # (module.class.field) or (config_key) — none required at this version.
}


def _allowed(qualified_name: str) -> bool:
    return qualified_name in ALLOWED_EXCEPTIONS


class TestNoCredentialFieldsInSchema:
    def test_schema_records(self):
        """Every SQLAlchemy Column name across the ORM must be clean."""
        from honeysnatch.db import schema as db_schema

        offenders = []
        for name, obj in inspect.getmembers(db_schema):
            if not inspect.isclass(obj):
                continue
            table = getattr(obj, "__tablename__", None)
            if not table:
                continue  # not a mapped class
            for col in obj.__table__.columns:  # type: ignore[attr-defined]
                qualified = f"schema.{name}.{col.name}"
                if FORBIDDEN.search(col.name) and not _allowed(qualified):
                    offenders.append(qualified)

        assert not offenders, (
            "F-17 regression: credential-shaped columns found in the "
            f"database schema: {offenders}. Either rename them or add "
            "them to ALLOWED_EXCEPTIONS with a written justification."
        )


class TestNoCredentialFieldsInModels:
    def test_core_models(self):
        """Every dataclass field on core.models must be clean."""
        from dataclasses import fields, is_dataclass
        from honeysnatch.core import models as core_models

        offenders = []
        for name, obj in inspect.getmembers(core_models):
            if not (inspect.isclass(obj) and is_dataclass(obj)):
                continue
            for field in fields(obj):
                qualified = f"core.models.{name}.{field.name}"
                if FORBIDDEN.search(field.name) and not _allowed(qualified):
                    offenders.append(qualified)

        assert not offenders, (
            f"F-17 regression: credential-shaped fields in core models: {offenders}"
        )


class TestNoCredentialFieldsInDefaultConfig:
    def test_default_config_yaml(self):
        """`data/default_config.yaml` must not name a credential key."""
        import yaml

        cfg_path = Path(__file__).resolve().parent.parent / "data" / "default_config.yaml"
        if not cfg_path.exists():
            pytest.skip(f"default config not found at {cfg_path}")
        cfg = yaml.safe_load(cfg_path.read_text()) or {}

        offenders = []

        def walk(prefix, node):
            if isinstance(node, dict):
                for k, v in node.items():
                    key = f"{prefix}.{k}" if prefix else k
                    if FORBIDDEN.search(k) and not _allowed(key):
                        offenders.append(key)
                    walk(key, v)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(f"{prefix}[{i}]", item)

        walk("", cfg)
        assert not offenders, (
            f"F-17 regression: credential-shaped keys in default config: {offenders}"
        )
