"""Cell tower classification and risk assessment for CellGuard.

Classifies cell towers by technology, band, operator, and evaluates
risk indicators for potential rogue base stations.
"""

from __future__ import annotations

from honeysnatch.cellular.models import CellTower, lookup_operator
from honeysnatch.utils.logger import get_logger

log = get_logger("cellular.classifier")

# Technologies ranked by security (higher = more secure)
TECH_SECURITY = {
    "GSM": 1,    # A5/1 broken, no mutual authentication
    "UMTS": 2,   # Better, but downgrade attacks possible
    "LTE": 3,    # Mutual auth, but pre-auth messages unprotected
    "5G_NR": 4,  # Best, with SUPI concealment
}

# Signal strength categories
SIGNAL_CATEGORIES = {
    "excellent": (-50, 0),
    "good": (-70, -50),
    "fair": (-85, -70),
    "weak": (-100, -85),
    "very_weak": (-120, -100),
}


def classify_cell_tower(tower: CellTower) -> dict:
    """Classify a cell tower and assess risk.

    Args:
        tower: The CellTower to classify.

    Returns:
        Dictionary with classification and risk details.
    """
    # Resolve operator if not already set
    operator = tower.operator
    if not operator and tower.mcc and tower.mnc:
        operator = lookup_operator(tower.mcc, tower.mnc)

    # Signal category
    signal_cat = "unknown"
    for cat, (lo, hi) in SIGNAL_CATEGORIES.items():
        if lo <= tower.rssi < hi:
            signal_cat = cat
            break

    # Technology security level
    tech_security = TECH_SECURITY.get(tower.technology, 0)

    # Risk assessment
    risk = "low"
    risk_reasons = []

    if tower.technology == "GSM":
        risk_reasons.append("GSM uses breakable A5/1 encryption")
    if tower.rssi > -50:
        risk_reasons.append(f"Very strong signal ({tower.rssi} dBm)")
    if not tower.plmn:
        risk_reasons.append("No operator identity (MCC/MNC missing)")
    if not operator and tower.plmn:
        risk_reasons.append(f"Unknown operator PLMN {tower.plmn}")

    if len(risk_reasons) >= 2:
        risk = "high"
    elif risk_reasons:
        risk = "medium"

    return {
        "cell_id": tower.cell_id,
        "technology": tower.technology,
        "plmn": tower.plmn,
        "operator": operator,
        "band": tower.band,
        "frequency_mhz": tower.frequency_mhz,
        "rssi": tower.rssi,
        "signal_category": signal_cat,
        "tech_security_level": tech_security,
        "risk": risk,
        "risk_reasons": risk_reasons,
    }
