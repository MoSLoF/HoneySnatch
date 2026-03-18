"""Tests for CellGuard rogue base station detector."""

import pytest

from honeysnatch.cellular.detector import (
    MAX_SIGNAL_DELTA,
    STRONG_SIGNAL_THRESHOLD,
    RogueBaseStationDetector,
)
from honeysnatch.cellular.models import CellTower


@pytest.fixture
def baseline_towers():
    """Known-good towers for baseline."""
    return [
        CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            tac=100, earfcn=5230, frequency_mhz=751.0, rssi=-75,
            band="Band 13", operator="T-Mobile",
        ),
        CellTower(
            cell_id="67890", technology="GSM", mcc="310", mnc="260",
            lac=200, arfcn=50, frequency_mhz=945.0, rssi=-80,
            band="GSM900", operator="T-Mobile",
        ),
        CellTower(
            cell_id="11111", technology="LTE", mcc="311", mnc="480",
            tac=300, earfcn=2525, frequency_mhz=881.5, rssi=-70,
            band="Band 5", operator="Verizon",
        ),
    ]


@pytest.fixture
def detector(baseline_towers):
    d = RogueBaseStationDetector()
    d.load_baseline(baseline_towers)
    return d


class TestUnknownCellId:
    """Heuristic 1: Tower not in baseline."""

    def test_unknown_tower_generates_alert(self, detector):
        tower = CellTower(
            cell_id="99999", technology="LTE", mcc="310", mnc="260",
            frequency_mhz=751.0, rssi=-70,
        )
        alerts = detector._check_unknown_cell_id(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "unknown_cell"

    def test_known_tower_no_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            tac=100, earfcn=5230, frequency_mhz=751.0, rssi=-75,
        )
        alerts = detector._check_unknown_cell_id(tower)
        assert len(alerts) == 0

    def test_no_baseline_no_alert(self):
        d = RogueBaseStationDetector()
        tower = CellTower(cell_id="99999", technology="LTE")
        assert d._check_unknown_cell_id(tower) == []


class TestSignalAnomaly:
    """Heuristic 2: Suspiciously strong signal."""

    def test_strong_signal_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-30,
        )
        alerts = detector._check_signal_anomaly(tower)
        assert any(a.alert_type == "strong_signal" for a in alerts)

    def test_normal_signal_no_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE",
            rssi=-75,
        )
        alerts = detector._check_signal_anomaly(tower)
        assert not any(a.alert_type == "strong_signal" for a in alerts)

    def test_signal_jump_alert(self, detector):
        # Set up previous scan
        prev_tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-90,
        )
        detector.update_previous_scan([prev_tower])

        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-40,
        )
        alerts = detector._check_signal_anomaly(tower)
        assert any(a.alert_type == "signal_jump" for a in alerts)


class TestEncryptionDowngrade:
    """Heuristic 3: Tower forcing 2G / no encryption."""

    def test_strong_gsm_with_lte_baseline(self, detector):
        tower = CellTower(
            cell_id="99999", technology="GSM", mcc="310", mnc="260",
            rssi=-40, operator="T-Mobile",
        )
        alerts = detector._check_encryption_downgrade(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "encryption_downgrade"
        assert alerts[0].severity == "critical"

    def test_weak_gsm_no_alert(self, detector):
        tower = CellTower(
            cell_id="99999", technology="GSM", mcc="310", mnc="260",
            rssi=-80, operator="T-Mobile",
        )
        alerts = detector._check_encryption_downgrade(tower)
        assert len(alerts) == 0

    def test_lte_tower_no_downgrade_alert(self, detector):
        tower = CellTower(
            cell_id="99999", technology="LTE", rssi=-40,
        )
        alerts = detector._check_encryption_downgrade(tower)
        assert len(alerts) == 0


class TestFrequencyAnomaly:
    """Heuristic 4: Tower on unexpected frequency."""

    def test_unexpected_band_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            band="Band 71", frequency_mhz=617.0, rssi=-75,
        )
        alerts = detector._check_frequency_anomaly(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "frequency_anomaly"

    def test_expected_band_no_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            band="Band 13", frequency_mhz=751.0, rssi=-75,
        )
        alerts = detector._check_frequency_anomaly(tower)
        assert len(alerts) == 0


class TestLacTacChange:
    """Heuristic 5: Location area changed."""

    def test_lac_change_alert(self, detector):
        tower = CellTower(
            cell_id="67890", technology="GSM", mcc="310", mnc="260",
            lac=999, arfcn=50, frequency_mhz=945.0, rssi=-80,
        )
        alerts = detector._check_lac_tac_change(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "lac_change"
        assert alerts[0].severity == "critical"

    def test_tac_change_alert(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            tac=999, earfcn=5230, frequency_mhz=751.0, rssi=-75,
        )
        alerts = detector._check_lac_tac_change(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "tac_change"

    def test_same_lac_no_alert(self, detector):
        tower = CellTower(
            cell_id="67890", technology="GSM", mcc="310", mnc="260",
            lac=200, arfcn=50, frequency_mhz=945.0, rssi=-80,
        )
        alerts = detector._check_lac_tac_change(tower)
        assert len(alerts) == 0


class TestOperatorMismatch:
    """Heuristic 6: Unknown operator."""

    def test_unknown_operator_alert(self, detector):
        tower = CellTower(
            cell_id="99999", technology="LTE", mcc="999", mnc="99",
            rssi=-70, operator="FakeCorp",
        )
        alerts = detector._check_operator_mismatch(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "operator_mismatch"

    def test_known_operator_no_alert(self, detector):
        tower = CellTower(
            cell_id="99999", technology="LTE", mcc="310", mnc="260",
            rssi=-70,
        )
        alerts = detector._check_operator_mismatch(tower)
        assert len(alerts) == 0


class TestRapidAppearance:
    """Heuristic 7: Tower appeared suddenly."""

    def test_rapid_appearance_alert(self, detector):
        # Set up previous scan without the new tower
        prev = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-75,
        )
        detector.update_previous_scan([prev])

        tower = CellTower(
            cell_id="88888", technology="LTE", mcc="310", mnc="260",
            rssi=-60, operator="T-Mobile",
        )
        alerts = detector._check_rapid_appearance(tower)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "rapid_appearance"

    def test_known_tower_no_rapid_alert(self, detector):
        prev = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-75,
        )
        detector.update_previous_scan([prev])

        # This tower IS in baseline, so no rapid_appearance alert
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-70,
        )
        alerts = detector._check_rapid_appearance(tower)
        assert len(alerts) == 0


class TestCheckTowerIntegration:
    """Integration test running all heuristics together."""

    def test_suspicious_tower_multiple_alerts(self, detector):
        prev = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-90,
        )
        detector.update_previous_scan([prev])

        # Suspicious: unknown, strong signal, unknown operator
        tower = CellTower(
            cell_id="FAKE1", technology="GSM", mcc="999", mnc="01",
            rssi=-30, operator="FakeCorp",
        )
        alerts = detector.check_tower(tower)
        assert len(alerts) >= 2
        types = {a.alert_type for a in alerts}
        assert "unknown_cell" in types
        assert "strong_signal" in types

    def test_benign_tower_no_alerts(self, detector):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            tac=100, earfcn=5230, frequency_mhz=751.0, rssi=-75,
            band="Band 13", operator="T-Mobile",
        )
        alerts = detector.check_tower(tower)
        assert len(alerts) == 0


class TestBaselinePersistence:
    """Test baseline save/load."""

    def test_save_and_load_baseline(self, tmp_path, baseline_towers):
        path = str(tmp_path / "baseline.json")
        d1 = RogueBaseStationDetector()
        d1.save_baseline(baseline_towers, path)

        d2 = RogueBaseStationDetector()
        d2.load_baseline_file(path)
        assert len(d2._baseline) == len(baseline_towers)
