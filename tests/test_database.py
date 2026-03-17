"""Tests for database manager and round-trip persistence."""

import pytest

from flyinghoneysnitch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    GeoPosition,
)
from flyinghoneysnitch.db.database import DatabaseManager, create_session_db


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    return DatabaseManager(db_path)


@pytest.fixture
def db_with_session(db):
    session_id = db.create_scan_session(name="Test", interface="wlan0", channels=[1, 6, 11])
    return db, session_id


class TestSessionCrud:

    def test_create_session(self, db):
        session_id = db.create_scan_session(name="MyScan")
        assert len(session_id) == 16

    def test_list_sessions(self, db):
        db.create_scan_session(name="Scan1")
        db.create_scan_session(name="Scan2")
        sessions = db.list_sessions()
        assert len(sessions) == 2

    def test_end_session(self, db):
        session_id = db.create_scan_session()
        db.end_scan_session(session_id)
        sessions = db.list_sessions()
        assert sessions[0]["end_time"] is not None


class TestAccessPointPersistence:

    def test_save_and_load_ap(self, db_with_session):
        db, session_id = db_with_session
        ap = AccessPoint(
            bssid="00:11:22:33:44:55",
            ssid="TestNet",
            channel=6,
            frequency=2437,
            rssi=-65,
            encryption=EncryptionType.WPA2,
            band=Band.BAND_2_4GHZ,
            vendor="Test Inc",
        )
        db.save_access_point(session_id, ap)

        loaded = db.load_scan_session(session_id)
        assert loaded is not None
        assert "00:11:22:33:44:55" in loaded.access_points
        loaded_ap = loaded.access_points["00:11:22:33:44:55"]
        assert loaded_ap.ssid == "TestNet"
        assert loaded_ap.channel == 6
        assert loaded_ap.encryption == EncryptionType.WPA2

    def test_update_ap(self, db_with_session):
        db, session_id = db_with_session
        ap = AccessPoint(
            bssid="00:11:22:33:44:55", ssid="TestNet", channel=6,
            frequency=2437, rssi=-65, encryption=EncryptionType.WPA2,
            band=Band.BAND_2_4GHZ,
        )
        db.save_access_point(session_id, ap)

        ap.rssi = -50
        ap.beacon_count = 200
        db.save_access_point(session_id, ap)

        loaded = db.load_scan_session(session_id)
        assert loaded.access_points["00:11:22:33:44:55"].rssi == -50

    def test_ap_with_position(self, db_with_session):
        db, session_id = db_with_session
        ap = AccessPoint(
            bssid="00:11:22:33:44:55", ssid="GeoNet", channel=1,
            frequency=2412, rssi=-60, encryption=EncryptionType.WPA2,
            band=Band.BAND_2_4GHZ,
        )
        ap.position = GeoPosition(latitude=38.9072, longitude=-77.0369)
        db.save_access_point(session_id, ap)

        loaded = db.load_scan_session(session_id)
        loaded_ap = loaded.access_points["00:11:22:33:44:55"]
        assert loaded_ap.position is not None
        assert loaded_ap.position.latitude == pytest.approx(38.9072)


class TestClientPersistence:

    def test_save_and_load_client(self, db_with_session):
        db, session_id = db_with_session
        client = Client(
            mac="aa:bb:cc:11:22:33",
            bssid="00:11:22:33:44:55",
            rssi=-60,
            vendor="ClientCo",
            probe_requests=["Net1", "Net2"],
            data_count=10,
        )
        db.save_client(session_id, client)

        loaded = db.load_scan_session(session_id)
        assert "aa:bb:cc:11:22:33" in loaded.clients
        loaded_cl = loaded.clients["aa:bb:cc:11:22:33"]
        assert loaded_cl.vendor == "ClientCo"
        assert "Net1" in loaded_cl.probe_requests

    def test_update_client_probes(self, db_with_session):
        db, session_id = db_with_session
        client = Client(
            mac="aa:bb:cc:11:22:33", rssi=-60,
            probe_requests=["Net1"],
        )
        db.save_client(session_id, client)

        client.probe_requests = ["Net2"]
        db.save_client(session_id, client)

        loaded = db.load_scan_session(session_id)
        probes = loaded.clients["aa:bb:cc:11:22:33"].probe_requests
        assert "Net1" in probes
        assert "Net2" in probes


class TestAlertPersistence:

    def test_save_alert(self, db):
        db.save_alert(
            alert_type="rogue_ap",
            message="Unauthorized AP detected",
            severity="critical",
            bssid="ff:ff:ff:ff:ff:ff",
        )
        # No load method for alerts standalone — just verify no exception


class TestCreateSessionDb:

    def test_creates_file(self, tmp_path):
        db = create_session_db(str(tmp_path), session_name="MyTest")
        assert db.db_path.endswith(".db")
        assert "MyTest" in db.db_path
        db.close()

    def test_encrypted_flag(self, tmp_path):
        db = DatabaseManager(str(tmp_path / "plain.db"))
        assert not db.is_encrypted
        db.close()


class TestLoadNonexistentSession:

    def test_returns_none(self, db):
        assert db.load_scan_session("nonexistent") is None
