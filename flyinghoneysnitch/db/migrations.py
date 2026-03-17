"""Simple schema migration support for FlyingHoneySnitch databases.

Tracks schema version in a metadata table and applies migrations sequentially.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("migrations")

CURRENT_VERSION = 2

MIGRATIONS: dict[int, list[str]] = {
    # Version 1: Initial schema (created by schema.py Base.metadata.create_all)
    1: [],
    # Version 2: Add isolation testing tables
    2: [
        """CREATE TABLE IF NOT EXISTS isolation_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id VARCHAR(64) UNIQUE NOT NULL,
            name VARCHAR(256) DEFAULT '',
            interface VARCHAR(64) DEFAULT '',
            second_interface VARCHAR(64) DEFAULT '',
            target_ssid VARCHAR(256) DEFAULT '',
            target_bssid VARCHAR(17) DEFAULT '',
            config_file VARCHAR(512) DEFAULT '',
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            notes TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS isolation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES isolation_sessions(id),
            attack_type VARCHAR(64) NOT NULL,
            outcome VARCHAR(32) NOT NULL,
            target_bssid VARCHAR(17) DEFAULT '',
            target_ssid VARCHAR(256) DEFAULT '',
            victim_identity VARCHAR(256) DEFAULT '',
            attacker_identity VARCHAR(256) DEFAULT '',
            victim_mac VARCHAR(17) DEFAULT '',
            attacker_mac VARCHAR(17) DEFAULT '',
            details TEXT DEFAULT '',
            duration_seconds REAL DEFAULT 0.0,
            timestamp TIMESTAMP,
            raw_log TEXT DEFAULT ''
        )""",
    ],
}


def get_schema_version(db: Session) -> int:
    """Get the current schema version from the database."""
    try:
        result = db.execute(text("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"))
        row = result.fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def ensure_version_table(db: Session) -> None:
    """Create the schema_version table if it doesn't exist."""
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    db.commit()


def migrate(db: Session) -> None:
    """Apply any pending migrations."""
    ensure_version_table(db)
    current = get_schema_version(db)

    if current >= CURRENT_VERSION:
        return

    for version in range(current + 1, CURRENT_VERSION + 1):
        statements = MIGRATIONS.get(version, [])
        for stmt in statements:
            db.execute(text(stmt))
        db.execute(
            text("INSERT INTO schema_version (version) VALUES (:v)"),
            {"v": version},
        )
        db.commit()
        log.info("Applied migration to version %d", version)
