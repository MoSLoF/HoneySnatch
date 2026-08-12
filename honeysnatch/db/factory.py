"""Central storage factory that honours SecurityConfig (review HS-04).

Prior to this factory, the two SecurityConfig flags
`encrypt_database` and `audit_enabled` had zero readers in the codebase
— operators could enable them and get plaintext SQLite + no audit
events anyway. Every entry point (CLI, GUI, analysis, exports) now
opens storage through :func:`open_database`, which:

  1. Reads SecurityConfig from the passed AppConfig (or a fresh one).
  2. Prompts for or reads the encryption passphrase when
     `encrypt_database` is set. Sources, in order:
        - `HBV_DB_PASSPHRASE` env var
        - explicit `passphrase` argument (for programmatic callers)
        - interactive `getpass()` if stdin is a TTY
     Fails closed if no passphrase can be obtained.
  3. Fails closed if sqlcipher3 / pysqlcipher3 isn't importable when
     encryption is requested — no silent fallback to plaintext.
  4. Emits an audit event for the open when `audit_enabled` is set.

Also exports :func:`audit_event` — the single entry point every other
module uses to emit audit events. It honours `audit_enabled` and
degrades silently when audit is off, so callers don't need conditionals.
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Optional

from honeysnatch.db.database import DatabaseManager
from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("db.factory")


class StorageConfigError(RuntimeError):
    """Raised when SecurityConfig demands encryption but we can't honour it."""


def _get_passphrase(explicit: Optional[str]) -> str:
    """Resolve the DB encryption passphrase, fail closed on absence."""
    if explicit:
        return explicit
    env = os.environ.get("HBV_DB_PASSPHRASE")
    if env:
        return env
    if sys.stdin.isatty():
        return getpass.getpass("Database encryption passphrase: ")
    raise StorageConfigError(
        "security.encrypt_database is enabled but no passphrase available. "
        "Set HBV_DB_PASSPHRASE, pass passphrase=..., or run from a TTY so "
        "the passphrase can be entered interactively."
    )


def _check_sqlcipher_available() -> None:
    """Import-probe SQLCipher; raise loudly if missing."""
    try:
        import sqlcipher3  # noqa: F401
        return
    except ImportError:
        pass
    try:
        import pysqlcipher3  # noqa: F401
        return
    except ImportError:
        pass
    raise StorageConfigError(
        "security.encrypt_database is enabled but no SQLCipher driver is "
        "installed. `pip install honeysnatch[encrypted_db]` or "
        "`pip install sqlcipher3`. Refusing to fall back to plaintext."
    )


def open_database(
    db_path: str,
    config: Optional[AppConfig] = None,
    passphrase: Optional[str] = None,
) -> DatabaseManager:
    """Open a DatabaseManager, honouring the security config.

    Args:
        db_path: Path to the SQLite/SQLCipher file.
        config: AppConfig; defaults to a fresh instance (which reads env).
        passphrase: Optional explicit passphrase override for tests /
            programmatic callers. Ignored when encryption is off.

    Raises:
        StorageConfigError: encryption is requested but no key / no driver.
    """
    if config is None:
        config = AppConfig()
    sec = config.security

    encryption_key = ""
    if sec.encrypt_database:
        _check_sqlcipher_available()
        encryption_key = _get_passphrase(passphrase)

    db = DatabaseManager(db_path, encryption_key=encryption_key)

    # HS-04/NR-02: encrypted opens are security-sensitive and must
    # produce a durable audit record. If the audit write fails (disk
    # full, permission denied, log file tampered) we roll back the
    # open — the operator's chosen policy said audit is authoritative
    # for encrypted storage. Plaintext opens are ordinary telemetry
    # and stay best-effort.
    try:
        if db.is_encrypted:
            audit_event_or_fail(
                "database_opened_encrypted",
                {"path": db_path},
                config=config,
            )
        else:
            audit_event(
                "database_opened",
                {"path": db_path, "encrypted": False},
                config=config,
            )
    except (AuditDisabledError, AuditWriteError):
        db.close()
        raise
    return db


def audit_event(
    event: str,
    data: Optional[dict] = None,
    config: Optional[AppConfig] = None,
) -> None:
    """Record a best-effort audit event, honouring `audit_enabled` (HS-04).

    When audit is disabled in config, this is a no-op — callers don't
    need to check the flag themselves.

    Best-effort semantics: audit-logger exceptions are LOGGED but do
    not propagate. Use :func:`audit_event_or_fail` for security-critical
    events (isolation consent grants, encryption openings, etc.) where
    silent audit loss is unacceptable — HS-03R remediation.
    """
    if config is None:
        config = AppConfig()
    if not config.security.audit_enabled:
        return
    from honeysnatch.utils.audit import get_audit_logger
    try:
        get_audit_logger().record(event, data or {})
    except Exception as exc:
        log.error("audit_event(%s) failed: %s", event, exc)


def audit_event_or_fail(
    event: str,
    data: Optional[dict] = None,
    config: Optional[AppConfig] = None,
) -> None:
    """Record a security-critical audit event; propagate on failure.

    HS-03R remediation: certain events (consent grants, encrypted-DB
    opens, isolation authorization) are the tamper-evidence record for
    a live operation. If audit is disabled OR the audit logger raises,
    the caller MUST fail closed — not proceed with the underlying
    operation.

    Raises:
        AuditDisabledError: audit_enabled is False.
        AuditWriteError: the audit logger raised.
    """
    if config is None:
        config = AppConfig()
    if not config.security.audit_enabled:
        raise AuditDisabledError(
            f"security-critical event {event!r} refused: security.audit_enabled "
            "is False. Enable audit or accept the safety property will not hold."
        )
    from honeysnatch.utils.audit import get_audit_logger
    try:
        get_audit_logger().record(event, data or {})
    except Exception as exc:
        raise AuditWriteError(
            f"security-critical event {event!r} could not be recorded: {exc}"
        ) from exc


class AuditDisabledError(RuntimeError):
    """audit_event_or_fail called while security.audit_enabled=False."""


class AuditWriteError(RuntimeError):
    """audit_event_or_fail encountered an audit-logger exception."""


def audit_active() -> bool:
    """Report whether audit is currently active — for `fhs info` etc."""
    return AppConfig().security.audit_enabled
