"""Tests for the 802.11 packet parser.

These tests use the parser's internal helper functions since
creating full scapy Dot11 packets is complex.
"""

import pytest

from flyinghoneysnitch.core.packet_parser import (
    _channel_to_band,
    _frequency_to_band,
    _frequency_to_channel,
    _parse_rates,
)
from flyinghoneysnitch.core.models import Band
from flyinghoneysnitch.core.oui_lookup import _normalize_prefix


class TestFrequencyConversion:
    def test_2_4ghz_channels(self):
        assert _frequency_to_channel(2412) == 1
        assert _frequency_to_channel(2437) == 6
        assert _frequency_to_channel(2462) == 11
        assert _frequency_to_channel(2484) == 14

    def test_5ghz_channels(self):
        assert _frequency_to_channel(5180) == 36
        assert _frequency_to_channel(5240) == 48
        assert _frequency_to_channel(5745) == 149
        assert _frequency_to_channel(5825) == 165

    def test_unknown_frequency(self):
        assert _frequency_to_channel(0) == 0
        assert _frequency_to_channel(900) == 0


class TestBandDetection:
    def test_channel_to_band(self):
        assert _channel_to_band(1) == Band.BAND_2_4GHZ
        assert _channel_to_band(6) == Band.BAND_2_4GHZ
        assert _channel_to_band(14) == Band.BAND_2_4GHZ
        assert _channel_to_band(36) == Band.BAND_5GHZ
        assert _channel_to_band(165) == Band.BAND_5GHZ

    def test_frequency_to_band(self):
        assert _frequency_to_band(2412) == Band.BAND_2_4GHZ
        assert _frequency_to_band(5180) == Band.BAND_5GHZ
        assert _frequency_to_band(5955) == Band.BAND_6GHZ


class TestRateParsing:
    def test_parse_rates(self):
        # 1 Mbps = 0x02 (1 * 2), 11 Mbps = 0x16 (11 * 2)
        data = bytes([0x82, 0x84, 0x8B, 0x96])  # 1, 2, 5.5, 11 Mbps (basic rates)
        rates = _parse_rates(data)
        assert 1.0 in rates
        assert 2.0 in rates
        assert 5.5 in rates
        assert 11.0 in rates


class TestOuiNormalize:
    def test_colon_format(self):
        assert _normalize_prefix("AA:BB:CC:DD:EE:FF") == "AA:BB:CC"

    def test_dash_format(self):
        assert _normalize_prefix("AA-BB-CC-DD-EE-FF") == "AA:BB:CC"

    def test_no_separator(self):
        assert _normalize_prefix("AABBCCDDEEFF") == "AA:BB:CC"

    def test_lowercase(self):
        assert _normalize_prefix("aa:bb:cc:dd:ee:ff") == "AA:BB:CC"

    def test_short_input(self):
        assert _normalize_prefix("AA:BB") == ""

    def test_invalid_chars(self):
        assert _normalize_prefix("XX:YY:ZZ:DD:EE:FF") == ""
