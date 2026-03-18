"""Shared test fixtures for honeysnatch."""

from datetime import datetime

import pytest

from honeysnatch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
    GeoPosition,
    ScanSession,
)
from honeysnatch.cellular.models import CellTower


@pytest.fixture
def sample_ap() -> AccessPoint:
    """A sample access point for testing."""
    return AccessPoint(
        bssid="00:11:22:33:44:55",
        ssid="TestNetwork",
        channel=6,
        frequency=2437,
        rssi=-65,
        encryption=EncryptionType.WPA2,
        cipher="CCMP",
        auth="PSK",
        band=Band.BAND_2_4GHZ,
        vendor="TestVendor Inc",
        hidden=False,
        beacon_count=100,
        data_count=50,
        wps=False,
    )


@pytest.fixture
def sample_hidden_ap() -> AccessPoint:
    """A sample hidden access point."""
    return AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="",
        channel=11,
        frequency=2462,
        rssi=-70,
        encryption=EncryptionType.WPA2,
        band=Band.BAND_2_4GHZ,
        hidden=True,
    )


@pytest.fixture
def sample_open_ap() -> AccessPoint:
    """A sample open (no encryption) access point."""
    return AccessPoint(
        bssid="11:22:33:44:55:66",
        ssid="OpenCafe",
        channel=1,
        frequency=2412,
        rssi=-55,
        encryption=EncryptionType.OPEN,
        band=Band.BAND_2_4GHZ,
    )


@pytest.fixture
def sample_client() -> Client:
    """A sample wireless client."""
    return Client(
        mac="aa:bb:cc:11:22:33",
        bssid="00:11:22:33:44:55",
        ssid="TestNetwork",
        rssi=-60,
        vendor="ClientVendor",
        probe_requests=["TestNetwork", "HomeWifi", "WorkNet"],
        data_count=25,
    )


@pytest.fixture
def sample_position() -> GeoPosition:
    """A sample GPS position (Washington DC area)."""
    return GeoPosition(
        latitude=38.9072,
        longitude=-77.0369,
        altitude=50.0,
        accuracy=5.0,
        source="gps",
    )


@pytest.fixture
def sample_session(sample_ap, sample_hidden_ap, sample_open_ap, sample_client) -> ScanSession:
    """A sample scan session with multiple devices."""
    session = ScanSession(
        session_id="test_session_001",
        name="Test Scan",
        interface="wlan0mon",
        channels=[1, 6, 11],
    )
    session.add_ap(sample_ap)
    session.add_ap(sample_hidden_ap)
    session.add_ap(sample_open_ap)
    session.add_client(sample_client)
    return session


@pytest.fixture
def sample_cell_tower() -> CellTower:
    """A sample LTE cell tower."""
    return CellTower(
        cell_id="12345",
        technology="LTE",
        mcc="310",
        mnc="260",
        tac=100,
        earfcn=5230,
        frequency_mhz=751.0,
        rssi=-75,
        band="Band 13",
        operator="T-Mobile",
    )


@pytest.fixture
def sample_gsm_tower() -> CellTower:
    """A sample GSM cell tower."""
    return CellTower(
        cell_id="67890",
        technology="GSM",
        mcc="310",
        mnc="260",
        lac=200,
        arfcn=50,
        frequency_mhz=945.0,
        rssi=-80,
        band="GSM900",
        operator="T-Mobile",
    )
