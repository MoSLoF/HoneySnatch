"""Tests for core data models."""

from datetime import datetime, timedelta

import pytest

from honeysnatch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    GeoPosition,
    ScanSession,
)


class TestAccessPoint:
    def test_create_ap(self, sample_ap):
        assert sample_ap.bssid == "00:11:22:33:44:55"
        assert sample_ap.ssid == "TestNetwork"
        assert sample_ap.channel == 6
        assert sample_ap.encryption == EncryptionType.WPA2
        assert not sample_ap.is_hidden

    def test_hidden_ap(self, sample_hidden_ap):
        assert sample_hidden_ap.is_hidden
        assert sample_hidden_ap.ssid == ""

    def test_update_rssi(self, sample_ap):
        sample_ap.update_rssi(-50)
        assert sample_ap.rssi == -50
        assert sample_ap.max_rssi == -50

        sample_ap.update_rssi(-70)
        assert sample_ap.rssi == -70
        assert sample_ap.max_rssi == -50  # Max preserved

    def test_update_rssi_with_position(self, sample_ap, sample_position):
        sample_ap.update_rssi(-40, sample_position)
        assert sample_ap.max_rssi == -40
        assert sample_ap.max_rssi_position == sample_position

    def test_age_seconds(self, sample_ap):
        age = sample_ap.age_seconds()
        assert age >= 0
        assert age < 5  # Should be very recent


class TestClient:
    def test_create_client(self, sample_client):
        assert sample_client.mac == "aa:bb:cc:11:22:33"
        assert sample_client.is_associated

    def test_not_associated(self):
        client = Client(mac="ff:ff:ff:00:00:01")
        assert not client.is_associated

    def test_add_probe(self, sample_client):
        sample_client.add_probe("NewNetwork")
        assert "NewNetwork" in sample_client.probe_requests

    def test_add_duplicate_probe(self, sample_client):
        count = len(sample_client.probe_requests)
        sample_client.add_probe("TestNetwork")  # Already exists
        assert len(sample_client.probe_requests) == count


class TestScanSession:
    def test_create_session(self, sample_session):
        assert sample_session.session_id == "test_session_001"
        assert sample_session.ap_count == 3
        assert sample_session.client_count == 1

    def test_add_new_ap(self, sample_session):
        new_ap = AccessPoint(bssid="ff:ff:ff:00:00:01", ssid="NewNet", channel=36)
        sample_session.add_ap(new_ap)
        assert sample_session.ap_count == 4

    def test_update_existing_ap(self, sample_session):
        updated_ap = AccessPoint(
            bssid="00:11:22:33:44:55",
            ssid="TestNetwork",
            rssi=-40,
            beacon_count=50,
        )
        sample_session.add_ap(updated_ap)
        assert sample_session.ap_count == 3  # Not added, updated
        assert sample_session.access_points["00:11:22:33:44:55"].beacon_count == 150  # 100 + 50

    def test_add_client(self, sample_session):
        new_client = Client(mac="ff:ff:ff:00:00:02", rssi=-75)
        sample_session.add_client(new_client)
        assert sample_session.client_count == 2

    def test_duration(self, sample_session):
        assert sample_session.duration_seconds >= 0


class TestGeoPosition:
    def test_create_position(self, sample_position):
        assert sample_position.latitude == 38.9072
        assert sample_position.longitude == -77.0369
        assert sample_position.source == "gps"


class TestEncryptionType:
    def test_values(self):
        assert EncryptionType.OPEN.value == "Open"
        assert EncryptionType.WPA2.value == "WPA2"
        assert EncryptionType.WPA3.value == "WPA3"

    def test_from_value(self):
        assert EncryptionType("WPA2") == EncryptionType.WPA2
