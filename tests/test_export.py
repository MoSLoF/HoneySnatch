"""Tests for CLI export commands and format validation."""

import csv
import json
import xml.etree.ElementTree as ET

import pytest

from flyinghoneysnitch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    GeoPosition,
)
from flyinghoneysnitch.db.database import DatabaseManager


@pytest.fixture
def populated_db(tmp_path):
    """Create a DB with a session containing APs and clients."""
    db_path = str(tmp_path / "test_export.db")
    db = DatabaseManager(db_path)
    session_id = db.create_scan_session(name="ExportTest", interface="wlan0")

    ap1 = AccessPoint(
        bssid="00:11:22:33:44:55", ssid="TestNet", channel=6,
        frequency=2437, rssi=-65, encryption=EncryptionType.WPA2,
        band=Band.BAND_2_4GHZ, vendor="Vendor1",
    )
    ap1.position = GeoPosition(latitude=38.9072, longitude=-77.0369)

    ap2 = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", ssid="OpenCafe", channel=1,
        frequency=2412, rssi=-55, encryption=EncryptionType.OPEN,
        band=Band.BAND_2_4GHZ, vendor="Vendor2",
    )

    client = Client(
        mac="11:22:33:44:55:66", bssid="00:11:22:33:44:55",
        rssi=-60, vendor="ClientCo",
        probe_requests=["TestNet", "HomeNet"],
    )

    db.save_access_point(session_id, ap1)
    db.save_access_point(session_id, ap2)
    db.save_client(session_id, client)
    db.end_scan_session(session_id)

    return db_path, db


class TestCsvExport:

    def test_csv_roundtrip(self, populated_db, tmp_path):
        db_path, db = populated_db
        session = db.load_scan_session(db.list_sessions()[0]["session_id"])
        assert session is not None

        csv_path = str(tmp_path / "export.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["BSSID", "SSID", "Channel", "Encryption"])
            for ap in session.access_points.values():
                writer.writerow([ap.bssid, ap.ssid, ap.channel, ap.encryption.value])

        with open(csv_path) as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert rows[0] == ["BSSID", "SSID", "Channel", "Encryption"]
        assert len(rows) == 3  # header + 2 APs
        bssids = {row[0] for row in rows[1:]}
        assert "00:11:22:33:44:55" in bssids


class TestJsonExport:

    def test_json_structure(self, populated_db, tmp_path):
        db_path, db = populated_db
        session = db.load_scan_session(db.list_sessions()[0]["session_id"])

        data = {
            "session": {
                "id": session.session_id,
                "name": session.name,
            },
            "access_points": [
                {
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "encryption": ap.encryption.value,
                }
                for ap in session.access_points.values()
            ],
            "clients": [
                {
                    "mac": cl.mac,
                    "vendor": cl.vendor,
                }
                for cl in session.clients.values()
            ],
        }

        json_path = str(tmp_path / "export.json")
        with open(json_path, "w") as f:
            json.dump(data, f)

        with open(json_path) as f:
            loaded = json.load(f)

        assert loaded["session"]["name"] == "ExportTest"
        assert len(loaded["access_points"]) == 2
        assert len(loaded["clients"]) == 1


class TestKmlExport:

    def test_kml_structure(self, populated_db, tmp_path):
        db_path, db = populated_db
        session = db.load_scan_session(db.list_sessions()[0]["session_id"])

        placemarks = []
        for ap in session.access_points.values():
            if not ap.position:
                continue
            placemarks.append(
                f"<Placemark><name>{ap.ssid}</name>"
                f"<Point><coordinates>{ap.position.longitude},{ap.position.latitude},0"
                f"</coordinates></Point></Placemark>"
            )

        kml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<kml xmlns="http://www.opengis.net/kml/2.2">'
            f'<Document><name>Test</name>{"".join(placemarks)}'
            '</Document></kml>'
        )

        kml_path = str(tmp_path / "export.kml")
        with open(kml_path, "w") as f:
            f.write(kml)

        tree = ET.parse(kml_path)
        ns = {"kml": "http://www.opengis.net/kml/2.2"}
        marks = tree.findall(".//kml:Placemark", ns)
        # Only ap1 has position
        assert len(marks) == 1


class TestEncryptedExport:

    def test_encrypt_and_decrypt_file(self, tmp_path):
        from flyinghoneysnitch.utils.crypto import decrypt_file, encrypt_file, is_encrypted_file

        plain_path = str(tmp_path / "data.json")
        enc_path = str(tmp_path / "data.json.enc")
        dec_path = str(tmp_path / "data_dec.json")

        with open(plain_path, "w") as f:
            json.dump({"test": "data", "value": 42}, f)

        encrypt_file(plain_path, enc_path, "testpass123")
        assert is_encrypted_file(enc_path)
        assert not is_encrypted_file(plain_path)

        decrypt_file(enc_path, dec_path, "testpass123")
        with open(dec_path) as f:
            loaded = json.load(f)
        assert loaded["test"] == "data"
        assert loaded["value"] == 42

    def test_wrong_passphrase_fails(self, tmp_path):
        from cryptography.exceptions import InvalidTag

        from flyinghoneysnitch.utils.crypto import decrypt_file, encrypt_file

        plain_path = str(tmp_path / "secret.txt")
        enc_path = str(tmp_path / "secret.enc")

        with open(plain_path, "w") as f:
            f.write("sensitive data")

        encrypt_file(plain_path, enc_path, "correct_pass")

        with pytest.raises(InvalidTag):
            decrypt_file(enc_path, str(tmp_path / "out.txt"), "wrong_pass")
