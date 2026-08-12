"""Configuration management for isolation testing.

Bridges between the wpa_supplicant .conf format used by AirSnitch
and the YAML-based configuration used by honeysnatch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class IsolationConfig:
    """Configuration for client isolation testing."""
    enabled: bool = False
    hostap_dir: str = ""
    wpa_supplicant_config: str = ""
    hostapd_config: str = ""
    default_server: str = "8.8.8.8"
    default_port: int = 443
    test_timeout: int = 30
    debug_level: int = 0


def find_hostap_binary(hostap_dir: str = "", ap: bool = False) -> Optional[str]:
    """Locate the hostapd or wpa_supplicant binary.

    HS-05 note: hostap is NOT packaged in the wheel. Search order:
      1. Explicit `hostap_dir` argument (test / operator override).
      2. `HBV_HOSTAP_DIR` env var (recommended for installed deployments —
         e.g. `HBV_HOSTAP_DIR=/opt/hbv/hostap_2_10`).
      3. `vendor/hostap_2_10/` relative to the source checkout (dev use).
      4. `vendor/hostap_2_10/` relative to project root (dev fallback).
    Returns None if not found; callers must display a clear message
    telling the operator that live-isolation is disabled.
    """
    import os

    binary_name = "hostapd" if ap else "wpa_supplicant"
    subdir = "hostapd" if ap else "wpa_supplicant"

    candidates: list[Path] = []
    if hostap_dir:
        candidates.append(Path(hostap_dir))
    env_dir = os.environ.get("HBV_HOSTAP_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(
        Path(__file__).resolve().parents[2] / "vendor" / "hostap_2_10"
    )
    candidates.append(
        Path(__file__).resolve().parents[3] / "vendor" / "hostap_2_10"
    )

    for base in candidates:
        cand = base / subdir / binary_name
        if cand.exists():
            return str(cand)

    return None


def find_default_config(config_type: str = "supplicant") -> Optional[str]:
    """Locate a bundled default configuration file.

    HS-05 remediation: prefer importlib.resources for the packaged copy
    so installed wheels work. Fall back to a source-checkout path for
    dev use where the package is `pip install -e .`.

    Args:
        config_type: "supplicant" or "hostapd" or a specific filename.
    """
    import importlib.resources as res

    if config_type == "supplicant":
        name = "client.conf"
    elif config_type == "hostapd":
        name = "hostapd.conf"
    else:
        name = config_type

    # Preferred: importlib.resources against the installed package.
    try:
        traversable = res.files("honeysnatch.data.isolation") / name
        if traversable.is_file():
            # as_file returns a context manager; for a real file on disk
            # (either sdist-extracted or editable install) the path is
            # stable so we can just str() the traversable.
            with res.as_file(traversable) as p:
                return str(p)
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass

    # Source-checkout fallback (pre-installed dev tree).
    for base in (
        Path(__file__).resolve().parents[1] / "data" / "isolation",   # honeysnatch/data
        Path(__file__).resolve().parents[2] / "data" / "isolation",   # legacy repo root
    ):
        candidate = base / name
        if candidate.exists():
            return str(candidate)

    return None
