"""Tests for the SentryWeb alert engine."""

import pytest

from flyinghoneysnitch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    ScanEvent,
)
from flyinghoneysnitch.monitoring.alerting import AlertEngine


@pytest.fixture
def engine():
    return AlertEngine(
        authorized_bssids={"00:11:22:33:44:55"},
        authorized_ssids={"CorpNet"},
        alert_on_rogue=True,
        alert_on_new_client=True,
        alert_on_open=True,
    )


def _make_ap(**kwargs):
    defaults = dict(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="TestAP",
        channel=6,
        frequency=2437,
        rssi=-65,
        encryption=EncryptionType.WPA2,
        band=Band.BAND_2_4GHZ,
    )
    defaults.update(kwargs)
    return AccessPoint(**defaults)


class TestRogueApDetection:

    def test_unauthorized_ap_generates_alert(self, engine):
        ap = _make_ap(bssid="ff:ff:ff:ff:ff:ff", ssid="RogueAP")
        event = ScanEvent(event_type="ap_found", ap=ap)
        alerts = engine.process_event(event)
        assert any(a["type"] == "rogue_ap" for a in alerts)

    def test_authorized_ap_no_rogue_alert(self, engine):
        ap = _make_ap(bssid="00:11:22:33:44:55", ssid="CorpNet")
        event = ScanEvent(event_type="ap_found", ap=ap)
        alerts = engine.process_event(event)
        assert not any(a["type"] == "rogue_ap" for a in alerts)


class TestEvilTwinDetection:

    def test_evil_twin_alert(self, engine):
        """Unauthorized AP using an authorized SSID."""
        ap = _make_ap(bssid="ff:ff:ff:ff:ff:ff", ssid="CorpNet")
        event = ScanEvent(event_type="ap_found", ap=ap)
        alerts = engine.process_event(event)
        assert any(a["type"] == "evil_twin" for a in alerts)
        assert any(a["severity"] == "critical" for a in alerts)


class TestOpenNetworkDetection:

    def test_open_network_alert(self, engine):
        ap = _make_ap(encryption=EncryptionType.OPEN, ssid="FreeCafe")
        event = ScanEvent(event_type="ap_found", ap=ap)
        alerts = engine.process_event(event)
        assert any(a["type"] == "open_network" for a in alerts)


class TestEncryptionDowngrade:

    def test_downgrade_alert(self, engine):
        ap = _make_ap(bssid="00:11:22:33:44:55", ssid="CorpNet", encryption=EncryptionType.WPA2)
        event = ScanEvent(event_type="ap_found", ap=ap)
        engine.process_event(event)

        # Now AP downgrades to WEP
        ap2 = _make_ap(bssid="00:11:22:33:44:55", ssid="CorpNet", encryption=EncryptionType.WEP)
        event2 = ScanEvent(event_type="ap_updated", ap=ap2)
        alerts = engine.process_event(event2)
        assert any(a["type"] == "encryption_downgrade" for a in alerts)


class TestSsidChange:

    def test_ssid_change_alert(self, engine):
        ap = _make_ap(bssid="00:11:22:33:44:55", ssid="CorpNet")
        engine.process_event(ScanEvent(event_type="ap_found", ap=ap))

        ap2 = _make_ap(bssid="00:11:22:33:44:55", ssid="EvilNet")
        alerts = engine.process_event(ScanEvent(event_type="ap_updated", ap=ap2))
        assert any(a["type"] == "ssid_change" for a in alerts)


class TestNewClientDetection:

    def test_new_client_alert(self, engine):
        client = Client(
            mac="aa:bb:cc:11:22:33",
            bssid="00:11:22:33:44:55",
            rssi=-60,
            vendor="TestVendor",
        )
        event = ScanEvent(event_type="client_found", client=client)
        alerts = engine.process_event(event)
        assert any(a["type"] == "new_client" for a in alerts)

    def test_known_client_no_alert(self, engine):
        client = Client(mac="aa:bb:cc:11:22:33", rssi=-60)
        engine.process_event(ScanEvent(event_type="client_found", client=client))

        # Second time - no alert
        alerts = engine.process_event(ScanEvent(event_type="client_found", client=client))
        assert not any(a["type"] == "new_client" for a in alerts)


class TestCellularEvents:

    def test_cell_tower_found_event(self, engine):
        event = ScanEvent(
            event_type="cell_tower_found",
            data={
                "technology": "LTE",
                "cell_id": "12345",
                "operator": "T-Mobile",
            },
        )
        alerts = engine.process_event(event)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "cell_tower_found"

    def test_rogue_tower_event(self, engine):
        event = ScanEvent(
            event_type="rogue_tower_detected",
            data={
                "severity": "critical",
                "message": "Suspected IMSI catcher detected",
            },
        )
        alerts = engine.process_event(event)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "rogue_tower"
        assert alerts[0]["severity"] == "critical"


class TestAlertCounting:

    def test_alert_count(self, engine):
        assert engine.alert_count == 0

        ap = _make_ap(encryption=EncryptionType.OPEN)
        engine.process_event(ScanEvent(event_type="ap_found", ap=ap))
        assert engine.alert_count > 0

    def test_get_alerts_returns_copy(self, engine):
        ap = _make_ap(encryption=EncryptionType.OPEN)
        engine.process_event(ScanEvent(event_type="ap_found", ap=ap))

        alerts = engine.get_alerts()
        alerts.clear()
        assert engine.alert_count > 0  # Original unaffected
