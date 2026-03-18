"""Tests for CellGuard data models and frequency utilities."""

import pytest

from honeysnatch.cellular.models import (
    CellTower,
    CellularDevice,
    arfcn_to_freq,
    earfcn_to_band,
    earfcn_to_freq,
)


class TestCellTower:

    def test_plmn(self):
        tower = CellTower(cell_id="123", technology="LTE", mcc="310", mnc="260")
        assert tower.plmn == "310-260"

    def test_plmn_empty(self):
        tower = CellTower(cell_id="123", technology="LTE")
        assert tower.plmn == ""

    def test_unique_id(self):
        tower = CellTower(cell_id="123", technology="LTE", mcc="310", mnc="260")
        assert tower.unique_id == "LTE:310-260:123"

    def test_update(self):
        tower = CellTower(cell_id="123", technology="LTE", rssi=-80)
        old_last_seen = tower.last_seen
        tower.update(rssi=-60)
        assert tower.rssi == -60
        assert tower.last_seen >= old_last_seen


class TestCellularDevice:

    def test_update(self):
        device = CellularDevice(identifier="TMSI_001", rssi=-90)
        device.update(rssi=-70)
        assert device.rssi == -70


class TestArfcnToFreq:

    def test_gsm900_arfcn_0(self):
        freq = arfcn_to_freq(0)
        assert freq == pytest.approx(935.0)

    def test_gsm900_arfcn_50(self):
        freq = arfcn_to_freq(50)
        assert freq == pytest.approx(945.0)

    def test_gsm900_arfcn_124(self):
        freq = arfcn_to_freq(124)
        assert freq == pytest.approx(959.8)

    def test_gsm1800_arfcn_512(self):
        freq = arfcn_to_freq(512)
        assert freq == pytest.approx(1805.2)

    def test_invalid_arfcn(self):
        assert arfcn_to_freq(9999) == 0.0


class TestEarfcnToFreq:

    def test_band1_earfcn_0(self):
        freq = earfcn_to_freq(0)
        assert freq == pytest.approx(2110.0)

    def test_band7_earfcn_2850(self):
        freq = earfcn_to_freq(2850)
        assert freq == pytest.approx(2630.0)

    def test_band13_earfcn_5180(self):
        freq = earfcn_to_freq(5180)
        assert freq == pytest.approx(746.0)

    def test_band71_earfcn_68586(self):
        freq = earfcn_to_freq(68586)
        assert freq == pytest.approx(617.0)

    def test_invalid_earfcn(self):
        assert earfcn_to_freq(999999) == 0.0


class TestEarfcnToBand:

    def test_band1(self):
        assert earfcn_to_band(300) == 1

    def test_band7(self):
        assert earfcn_to_band(3000) == 7

    def test_band13(self):
        assert earfcn_to_band(5200) == 13

    def test_band71(self):
        assert earfcn_to_band(68700) == 71

    def test_invalid(self):
        assert earfcn_to_band(999999) == 0
