"""Database manager for honeysnatch scan sessions.

Each scan session can be stored as an individual .fhs SQLite file
or in a shared database for continuous monitoring.  Supports optional
SQLCipher transparent encryption at rest.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from honeysnatch.core.models import (
    AccessPoint,
    Client,
    EncryptionType,
    GeoPosition,
    ScanSession,
)
from honeysnatch.db.schema import (
    AccessPointRecord,
    AlertRecord,
    Base,
    BluetoothDeviceRecord,
    CellRogueAlertRecord,
    CellTowerRecord,
    ClientRecord,
    IsolationResultRecord,
    IsolationSessionRecord,
    PositionRecord,
    SessionRecord,
    SignalRecord,
)
from honeysnatch.utils.logger import get_logger

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
        return self._encrypted

    def close(self) -> None:
        """Close the database connection."""
        self.engine.dispose()

    # ------------------------------------------------------------------
    # Scan session CRUD
    # ------------------------------------------------------------------

    def create_scan_session(
        self,
        name: str = "",
        interface: str = "",
        channels: Optional[list[int]] = None,
    ) -> str:
        """Create a new scan session record; return its session_id."""
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

    # ------------------------------------------------------------------
    # WiFi AP / Client
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # CellGuard — cell towers
    # ------------------------------------------------------------------

    def save_cell_tower(self, session_id: str, tower, is_baseline: bool = False) -> None:
        """Save or update a CellTower in the database.

        Args:
            session_id: Active scan session ID.
            tower:       A :class:`~honeysnatch.cellular.models.CellTower` instance.
            is_baseline: Mark this tower as a known-good baseline entry.
        """
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return

            existing = (
                db.query(CellTowerRecord)
                .filter_by(session_id=session_record.id, cell_id=tower.cell_id,
                           technology=tower.technology)
                .first()
            )

            if existing:
                existing.rssi = tower.rssi
                existing.last_seen = datetime.now()
                if tower.position:
                    existing.latitude = tower.position.latitude
                    existing.longitude = tower.position.longitude
                if is_baseline:
                    existing.is_baseline = True
            else:
                record = CellTowerRecord(
                    session_id=session_record.id,
                    cell_id=tower.cell_id,
                    technology=tower.technology,
                    mcc=tower.mcc,
                    mnc=tower.mnc,
                    lac=tower.lac,
                    tac=tower.tac,
                    arfcn=tower.arfcn,
                    earfcn=tower.earfcn,
                    frequency_mhz=tower.frequency_mhz,
                    rssi=tower.rssi,
                    band=tower.band,
                    operator=tower.operator,
                    pci=tower.pci,
                    first_seen=tower.first_seen,
                    last_seen=tower.last_seen,
                    latitude=tower.position.latitude if tower.position else None,
                    longitude=tower.position.longitude if tower.position else None,
                    is_baseline=is_baseline,
                )
                db.add(record)
            db.commit()

    def save_cell_rogue_alert(self, alert_dict: dict) -> None:
        """Persist a rogue base station alert.

        Args:
            alert_dict: Dict as returned by
                :meth:`~honeysnatch.cellular.detector.RogueAlert.to_dict`.
        """
        with self.get_session() as db:
            record = CellRogueAlertRecord(
                alert_type=alert_dict.get("type", ""),
                severity=alert_dict.get("severity", "warning"),
                message=alert_dict.get("message", ""),
                cell_id=alert_dict.get("cell_id", ""),
                technology=alert_dict.get("technology", ""),
                plmn=alert_dict.get("plmn", ""),
                frequency_mhz=alert_dict.get("frequency_mhz", 0.0),
                rssi=alert_dict.get("rssi", -120),
                details=json.dumps(alert_dict.get("details", {})),
            )
            db.add(record)
            db.commit()
        log.warning(
            "Rogue alert saved: [%s] %s",
            alert_dict.get("severity", "?").upper(),
            alert_dict.get("message", ""),
        )

    def list_cell_towers(self, session_id: str) -> list[dict]:
        """List all cell towers for a session."""
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return []
            return [
                {
                    "cell_id":       r.cell_id,
                    "technology":    r.technology,
                    "plmn":          f"{r.mcc}-{r.mnc}" if r.mcc else "",
                    "operator":      r.operator,
                    "band":          r.band,
                    "frequency_mhz": r.frequency_mhz,
                    "rssi":          r.rssi,
                    "is_baseline":   r.is_baseline,
                    "first_seen":    r.first_seen,
                    "last_seen":     r.last_seen,
                }
                for r in session_record.cell_towers
            ]

    # ------------------------------------------------------------------
    # BlueScout — bluetooth devices
    # ------------------------------------------------------------------

    def save_bt_device(self, session_id: str, device) -> None:
        """Save or update a BluetoothDevice in the database.

        Args:
            session_id: Active scan session ID.
            device:     A :class:`~honeysnatch.bluetooth.models.BluetoothDevice` instance.
        """
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return

            existing = (
                db.query(BluetoothDeviceRecord)
                .filter_by(session_id=session_record.id, address=device.address)
                .first()
            )

            adv = device.advertisement
            beacon_type = ""
            beacon_meta_json = ""
            service_uuids_str = ""
            tx_power = None
            is_connectable = False

            if adv:
                beacon_type = adv.beacon_meta.get("type", "") if adv.beacon_meta else ""
                beacon_meta_json = json.dumps(adv.beacon_meta) if adv.beacon_meta else ""
                service_uuids_str = ",".join(adv.service_uuids)
                tx_power = adv.tx_power
                is_connectable = adv.connectable

            risk_reasons_str = "; ".join(device.risk_reasons)

            if existing:
                existing.rssi = device.rssi
                existing.last_seen = device.last_seen
                existing.packet_count = device.packet_count
                existing.risk = device.risk
                existing.risk_reasons = risk_reasons_str
                if device.name and not existing.name:
                    existing.name = device.name
                if beacon_type and not existing.beacon_type:
                    existing.beacon_type = beacon_type
                    existing.beacon_meta = beacon_meta_json
                if device.position:
                    existing.latitude = device.position.latitude
                    existing.longitude = device.position.longitude
            else:
                record = BluetoothDeviceRecord(
                    session_id=session_record.id,
                    address=device.address,
                    device_type=device.device_type.value,
                    name=device.name,
                    manufacturer=device.manufacturer,
                    company_name=device.company_name,
                    device_class=device.device_class,
                    device_class_name=device.device_class_name,
                    rssi=device.rssi,
                    tx_power=tx_power,
                    beacon_type=beacon_type,
                    beacon_meta=beacon_meta_json,
                    service_uuids=service_uuids_str,
                    is_connectable=is_connectable,
                    risk=device.risk,
                    risk_reasons=risk_reasons_str,
                    packet_count=device.packet_count,
                    first_seen=device.first_seen,
                    last_seen=device.last_seen,
                    latitude=device.position.latitude if device.position else None,
                    longitude=device.position.longitude if device.position else None,
                )
                db.add(record)
            db.commit()

    def list_bt_devices(self, session_id: str) -> list[dict]:
        """List all Bluetooth devices for a session."""
        with self.get_session() as db:
            session_record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if not session_record:
                return []
            return [
                {
                    "address":      r.address,
                    "type":         r.device_type,
                    "name":         r.name,
                    "manufacturer": r.manufacturer,
                    "company":      r.company_name,
                    "beacon_type":  r.beacon_type,
                    "rssi":         r.rssi,
                    "risk":         r.risk,
                    "first_seen":   r.first_seen,
                    "last_seen":    r.last_seen,
                    "packet_count": r.packet_count,
                }
                for r in session_record.bluetooth_devices
            ]

    # ------------------------------------------------------------------
    # Position / Signal / Alert helpers (unchanged)
    # ------------------------------------------------------------------

    def save_position(self, session_id: str, position: GeoPosition) -> None:
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

    # ------------------------------------------------------------------
    # Session listing
    # ------------------------------------------------------------------

    def load_scan_session(self, session_id: str) -> Optional[ScanSession]:
        """Load a scan session with all its WiFi data."""
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
                    ap.position = GeoPosition(latitude=ap_rec.latitude, longitude=ap_rec.longitude)
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
        """List all scan sessions."""
        with self.get_session() as db:
            records = db.query(SessionRecord).order_by(SessionRecord.start_time.desc()).all()
            return [
                {
                    "session_id":    r.session_id,
                    "name":          r.name,
                    "start_time":    r.start_time,
                    "end_time":      r.end_time,
                    "interface":     r.interface,
                    "ap_count":      len(r.access_points),
                    "client_count":  len(r.clients),
                    "tower_count":   len(r.cell_towers),
                    "bt_count":      len(r.bluetooth_devices),
                }
                for r in records
            ]


def create_session_db(
    data_dir: str,
    session_name: str = "",
    encryption_key: str = "",
) -> "DatabaseManager":
    """Create a new session database file.

    Args:
        data_dir:       Directory to store the .fhs database file.
        session_name:   Optional name for the session.
        encryption_key: Optional passphrase for SQLCipher encryption.

    Returns:
        DatabaseManager for the new session database.
    """
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name_slug = session_name.replace(" ", "_")[:32] if session_name else "scan"
    db_path = str(Path(data_dir) / f"fhs_{name_slug}_{timestamp}.db")
    return DatabaseManager(db_path, encryption_key=encryption_key)
