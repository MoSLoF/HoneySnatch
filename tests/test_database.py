"""Tests for database manager and round-trip persistence."""

import pytest

from honeysnatch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    GeoPosition,
)
from honeysnatch.db.database import DatabaseManager, create_session_db


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


class TestEncryptionKeyNotInEngineUrl:
    """Review finding F-03: the SQLCipher key must NEVER be interpolated
    into the SQLAlchemy engine URL — URL parsing silently corrupts keys
    that contain `@`, `:`, `/`, `#`, `?`, or `%`, and the URL then leaks
    into DSN reprs and exception traces.

    These tests don't require the sqlcipher3 driver to be installed —
    they exercise the URL construction and the PRAGMA installation
    directly, so they run in any CI environment.
    """

    # Keys that broke the pre-F-03 URL interpolation.
    METACHAR_KEYS = [
        "pass@word",           # @ → username/host split
        "abc:def",             # : → username/password split
        "key/with/slashes",    # / → path segments
        "hash#fragment",       # # → URL fragment
        "query?param=v",       # ? → query string
        "percent%20encoded",   # % → percent-decode
        "'quote'day",          # ' → SQL literal terminator
        "everything@:/#?%'!",  # kitchen sink
    ]

    def _build_engine_url(self, key: str, db_path: str) -> str:
        """Ask DatabaseManager to construct the URL as it would in
        real use, without needing sqlcipher3 to actually connect."""
        from unittest.mock import patch
        from honeysnatch.db.database import DatabaseManager

        captured = {}

        def fake_create_engine(url, **kw):
            captured["url"] = str(url)
            # Return a mock engine minimally usable for constructor path.
            class _StubEngine:
                def dispose(self): pass
            return _StubEngine()

        # Stop the constructor from calling create_all + event.listens_for.
        with patch("honeysnatch.db.database.create_engine", fake_create_engine), \
             patch("honeysnatch.db.database.Base") as _base, \
             patch("honeysnatch.db.database.sessionmaker"), \
             patch.object(DatabaseManager, "_install_sqlcipher_pragma"):
            _base.metadata.create_all = lambda *_a, **_kw: None
            DatabaseManager(db_path, encryption_key=key)

        return captured["url"]

    @pytest.mark.parametrize("key", METACHAR_KEYS)
    def test_key_never_appears_in_engine_url(self, tmp_path, key):
        url = self._build_engine_url(key, str(tmp_path / "enc.db"))
        assert key not in url, (
            f"F-03 regression: SQLCipher key {key!r} was interpolated "
            f"into engine URL: {url!r}"
        )
        # And the URL still looks like a sqlcipher URL.
        assert url.startswith("sqlite+pysqlcipher:///")

    def test_pragma_escapes_single_quotes(self, tmp_path):
        """Any implementation of _install_sqlcipher_pragma MUST escape
        `'` to `''` — otherwise a key containing a quote produces a
        malformed PRAGMA statement.
        """
        from unittest.mock import MagicMock, patch
        from sqlalchemy import event
        from honeysnatch.db.database import DatabaseManager

        # Stub out sqlalchemy internals so we can capture the PRAGMA text.
        captured_sql = []

        class _FakeCursor:
            def execute(self, sql, *_a, **_kw): captured_sql.append(sql)
            def fetchall(self): return []
            def close(self): pass

        class _FakeConn:
            def cursor(self): return _FakeCursor()

        # Grab the registered event handler by intercepting event.listens_for.
        registered = {}
        def fake_listens_for(target, name):
            def _decorator(fn):
                registered.setdefault(name, []).append(fn)
                return fn
            return _decorator

        def fake_create_engine(url, **kw):
            class _StubEngine:
                def dispose(self): pass
            return _StubEngine()

        with patch("honeysnatch.db.database.create_engine", fake_create_engine), \
             patch("honeysnatch.db.database.event.listens_for", fake_listens_for), \
             patch("honeysnatch.db.database.Base") as _base, \
             patch("honeysnatch.db.database.sessionmaker"):
            _base.metadata.create_all = lambda *_a, **_kw: None
            DatabaseManager(str(tmp_path / "q.db"), encryption_key="it's")

        assert registered.get("connect"), "connect handler not registered"
        # Now invoke the captured handler as if a new connection just opened.
        registered["connect"][0](_FakeConn(), None)
        pragma = next((s for s in captured_sql if s.startswith("PRAGMA key")), None)
        assert pragma is not None, f"no PRAGMA key issued (captured: {captured_sql})"
        # The single quote in the key MUST be doubled — not raw, not backslash.
        assert "it''s" in pragma, (
            f"F-03 regression: quote not escaped as SQL literal: {pragma!r}"
        )
        assert "\\'" not in pragma, "backslash-escape is wrong for SQL literals"
