"""Tests for CellGuard tower classifier."""

import pytest

from honeysnatch.cellular.classifier import (
    SIGNAL_CATEGORIES,
    TECH_SECURITY,
    classify_cell_tower,
)
from honeysnatch.cellular.models import CellTower


class TestClassifyCellTower:

    def test_lte_tower_classification(self):
        tower = CellTower(
            cell_id="12345", technology="LTE", mcc="310", mnc="260",
            rssi=-65, band="Band 13", frequency_mhz=751.0,
        )
        result = classify_cell_tower(tower)
        assert result["technology"] == "LTE"
        assert result["tech_security_level"] == 3
        assert result["signal_category"] == "good"
        assert result["risk"] == "low"

    def test_gsm_tower_higher_risk(self):
        tower = CellTower(
            cell_id="67890", technology="GSM",
            rssi=-75, band="GSM900",
        )
        result = classify_cell_tower(tower)
        assert result["tech_security_level"] == 1
        assert result["risk"] in ("medium", "high")
        assert any("GSM" in r for r in result["risk_reasons"])

    def test_strong_signal_risk(self):
        tower = CellTower(
            cell_id="123", technology="LTE", mcc="310", mnc="260",
            rssi=-30, operator="T-Mobile",
        )
        result = classify_cell_tower(tower)
        assert any("strong signal" in r.lower() for r in result["risk_reasons"])

    def test_no_plmn_risk(self):
        tower = CellTower(
            cell_id="123", technology="LTE",
            rssi=-75,
        )
        result = classify_cell_tower(tower)
        assert any("MCC/MNC" in r for r in result["risk_reasons"])

    def test_excellent_signal(self):
        tower = CellTower(cell_id="1", technology="5G_NR", rssi=-45, mcc="310", mnc="260", operator="T")
        result = classify_cell_tower(tower)
        assert result["signal_category"] == "excellent"

    def test_weak_signal(self):
        tower = CellTower(cell_id="1", technology="LTE", rssi=-95, mcc="310", mnc="260", operator="T")
        result = classify_cell_tower(tower)
        assert result["signal_category"] == "weak"

    def test_5g_nr_security_level(self):
        tower = CellTower(cell_id="1", technology="5G_NR", rssi=-70, mcc="310", mnc="260", operator="T")
        result = classify_cell_tower(tower)
        assert result["tech_security_level"] == 4

    def test_gsm_strong_signal_high_risk(self):
        """GSM + strong signal = 2 risk factors = high risk."""
        tower = CellTower(
            cell_id="1", technology="GSM",
            rssi=-30,
        )
        result = classify_cell_tower(tower)
        assert result["risk"] == "high"
        assert len(result["risk_reasons"]) >= 2
