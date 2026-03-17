"""Database manager for FlyingHoneySnitch scan sessions.

Each scan session can be stored as an individual .fhs SQLite file
or in a shared database for continuous monitoring.  Supports optional
SQLCipher transparent encryption at rest.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from flyinghoneysnitch.core.models import (
    AccessPoint,
    Client,
    EncryptionType,
    GeoPosition,
    ScanSession,
)
from flyinghoneysnitch.db.schema import (
    AccessPointRecord,
    AlertRecord,
    Base,
    ClientRecord,
    IsolationResultRecord,
    IsolationSessionRecord,
    PositionRecord,
    SessionRecord,
    SignalRecord,
)
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("database")


class DatabaseManager:
    """Manages SQLite database connections for scan sessions.

    If ``encryption_key`` is provided, the database is opened with
    SQLCipher transparent encryption.  Requires the ``sqlcipher3``
    package to be installed (``pip install sqlcipher3``).
    """

    def __init__(self, db_path: str, encryption_key: str = "") -> None:
        self.db_path = db_path
        self._encrypted = bool(encryption_key)

        if self._encrypted:
            self.engine = create_engine(
                f"sqlite+pysqlcipher://:{encryption_key}@/{db_path}",
                echo=False,
            )
        else:
            self.engine = create_engine(f"sqlite:///{db_path}", echo=False)

        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)
        log.info(
            "Database initialized: %s%s", db_path,
            " (encrypted)" if self._encrypted else "",
        )

    def get_session(self) -> Session:
        """Get a new SQLAlchemy session."""
        return self._session_factory()

    @property
    def is_encrypted(self) -> bool:
        """Whether this database is using SQLCipher encryption."""
        return self._encrypted

    def close(self) -> None:
        """Close the database connection."""
        self.engine.dispose()

    # --- Session CRUD ---

    def create_scan_session(
        self,
        name: str = "",
        interface: str = "",
        channels: Optional[list[int]] = None,
    ) -> str:
        """Create a new scan session record.

        Returns:
            The generated session_id.
        """
        session_id = uuid4().hex[:16]
        with self.get_session() as db:
            record = SessionRecord(
                session_id=session_id,
                name=name or f"Scan {datetime.now():%Y-%m-%d %H:%M}",
                interface=interface,
                start_time=datetime.now(),
                channels=",".join(str(c) for c in (channels or [])),
            )
            db.add(record)
            db.commit()
        log.info("Created scan session: %s", session_id)
        return session_id

    def end_scan_session(self, session_id: str) -> None:
        """Mark a scan session as ended."""
        with self.get_session() as db:
            record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if record:
                record.end_time = datetime.now()
                db.commit()

    def save_access_point(self, session_id: str, ap: AccessPoint) -> None:
        """Save or update an access point in the database."""
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return

            existing = (
                db.query(AccessPointRecord)
                .filter_by(session_id=session_record.id, bssid=ap.bssid)
                .first()
            )

            if existing:
                existing.rssi = ap.rssi
                existing.max_rssi = max(existing.max_rssi, ap.rssi)
                existing.beacon_count = ap.beacon_count
                existing.data_count = ap.data_count
                existing.last_seen = ap.last_seen
                if ap.ssid:
                    existing.ssid = ap.ssid
                if ap.encryption != EncryptionType.UNKNOWN:
                    existing.encryption = ap.encryption.value
                if ap.position:
                    existing.latitude = ap.position.latitude
                    existing.longitude = ap.position.longitude
            else:
                record = AccessPointRecord(
                    session_id=session_record.id,
                    bssid=ap.bssid,
                    ssid=ap.ssid,
                    channel=ap.channel,
                    frequency=ap.frequency,
                    rssi=ap.rssi,
                    max_rssi=ap.max_rssi,
                    encryption=ap.encryption.value,
                    cipher=ap.cipher,
                    auth=ap.auth,
                    band=ap.band.value,
                    vendor=ap.vendor,
                    hidden=ap.hidden,
                    beacon_count=ap.beacon_count,
                    data_count=ap.data_count,
                    wps=ap.wps,
                    first_seen=ap.first_seen,
                    last_seen=ap.last_seen,
                    latitude=ap.position.latitude if ap.position else None,
                    longitude=ap.position.longitude if ap.position else None,
                )
                db.add(record)
            db.commit()

    def save_client(self, session_id: str, client: Client) -> None:
        """Save or update a client in the database."""
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return

            existing = (
                db.query(ClientRecord)
                .filter_by(session_id=session_record.id, mac=client.mac)
                .first()
            )

            if existing:
                existing.rssi = client.rssi
                existing.last_seen = client.last_seen
                existing.data_count = client.data_count
                if client.bssid:
                    existing.bssid = client.bssid
                probes = set(existing.probe_requests.split(",")) if existing.probe_requests else set()
                probes.update(client.probe_requests)
                probes.discard("")
                existing.probe_requests = ",".join(sorted(probes))
            else:
                record = ClientRecord(
                    session_id=session_record.id,
                    mac=client.mac,
                    bssid=client.bssid,
                    rssi=client.rssi,
                    vendor=client.vendor,
                    probe_requests=",".join(client.probe_requests),
                    data_count=client.data_count,
                    first_seen=client.first_seen,
                    last_seen=client.last_seen,
                    latitude=client.position.latitude if client.position else None,
                    longitude=client.position.longitude if client.position else None,
                )
                db.add(record)
            db.commit()

    def save_position(self, session_id: str, position: GeoPosition) -> None:
        """Save a GPS/IMU position track point."""
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return
            record = PositionRecord(
                session_id=session_record.id,
                latitude=position.latitude,
                longitude=position.longitude,
                altitude=position.altitude,
                accuracy=position.accuracy,
                source=position.source,
                timestamp=position.timestamp,
            )
            db.add(record)
            db.commit()

    def save_signal(self, bssid: str, rssi: int, position: Optional[GeoPosition] = None) -> None:
        """Save a signal strength measurement."""
        with self.get_session() as db:
            record = SignalRecord(
                bssid=bssid,
                rssi=rssi,
                latitude=position.latitude if position else None,
                longitude=position.longitude if position else None,
            )
            db.add(record)
            db.commit()

    def save_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "info",
        bssid: Optional[str] = None,
        mac: Optional[str] = None,
    ) -> None:
        """Save a security alert."""
        with self.get_session() as db:
            record = AlertRecord(
                alert_type=alert_type,
                severity=severity,
                message=message,
                bssid=bssid,
                mac=mac,
            )
            db.add(record)
            db.commit()

    def load_scan_session(self, session_id: str) -> Optional[ScanSession]:
        """Load a scan session with all its data."""
        with self.get_session() as db:
            record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not record:
                return None

            session = ScanSession(
                session_id=record.session_id,
                name=record.name,
                start_time=record.start_time,
                end_time=record.end_time,
                interface=record.interface,
                channels=[int(c) for c in record.channels.split(",") if c],
            )

            for ap_rec in record.access_points:
                ap = AccessPoint(
                    bssid=ap_rec.bssid,
                    ssid=ap_rec.ssid,
                    channel=ap_rec.channel,
                    frequency=ap_rec.frequency,
                    rssi=ap_rec.rssi,
                    encryption=EncryptionType(ap_rec.encryption),
                    vendor=ap_rec.vendor,
                    hidden=ap_rec.hidden,
                    beacon_count=ap_rec.beacon_count,
                    data_count=ap_rec.data_count,
                    first_seen=ap_rec.first_seen,
                    last_seen=ap_rec.last_seen,
                    max_rssi=ap_rec.max_rssi,
                )
                if ap_rec.latitude is not None:
                    ap.position = GeoPosition(
                        latitude=ap_rec.latitude,
                        longitude=ap_rec.longitude,
                    )
                session.access_points[ap.bssid] = ap

            for cl_rec in record.clients:
                client = Client(
                    mac=cl_rec.mac,
                    bssid=cl_rec.bssid,
                    rssi=cl_rec.rssi,
                    vendor=cl_rec.vendor,
                    probe_requests=[p for p in cl_rec.probe_requests.split(",") if p],
                    data_count=cl_rec.data_count,
                    first_seen=cl_rec.first_seen,
                    last_seen=cl_rec.last_seen,
                )
                session.clients[client.mac] = client

            return session

    def list_sessions(self) -> list[dict]:
        """List all scan sessions in the database."""
        with self.get_session() as db:
            records = db.query(SessionRecord).order_by(SessionRecord.start_time.desc()).all()
            return [
                {
                    "session_id": r.session_id,
                    "name": r.name,
                    "start_time": r.start_time,
                    "end_time": r.end_time,
                    "interface": r.interface,
                    "ap_count": len(r.access_points),
                    "client_count": len(r.clients),
                }
                for r in records
            ]


def create_session_db(
    data_dir: str,
    session_name: str = "",
    encryption_key: str = "",
) -> DatabaseManager:
    """Create a new session database file.

    Args:
        data_dir: Directory to store the .fhs database file.
        session_name: Optional name for the session.
        encryption_key: Optional passphrase for SQLCipher encryption.

    Returns:
        DatabaseManager for the new session database.
    """
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name_slug = session_name.replace(" ", "_")[:32] if session_name else "scan"
    db_path = str(Path(data_dir) / f"fhb_{name_slug}_{timestamp}.db")
    return DatabaseManager(db_path, encryption_key=encryption_key)
