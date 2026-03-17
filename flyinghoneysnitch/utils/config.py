"""Configuration management for FlyingHoneySnitch."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from flyinghoneysnitch.isolation.config import IsolationConfig

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "flyinghoneysnitch"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "flyinghoneysnitch"


@dataclass
class ScanConfig:
    """Scanner configuration."""

    interface: str = ""
    channels_2_4: list[int] = field(default_factory=lambda: list(range(1, 15)))
    channels_5: list[int] = field(
        default_factory=lambda: [
            36, 40, 44, 48, 52, 56, 60, 64,
            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
            149, 153, 157, 161, 165,
        ]
    )
    hop_interval: float = 0.5  # seconds between channel hops
    scan_5ghz: bool = True
    capture_pcap: bool = False
    pcap_dir: str = ""


@dataclass
class GpsConfig:
    """GPS daemon configuration."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 2947


@dataclass
class BluetoothConfig:
    """Bluetooth scanning configuration."""

    enabled: bool = False
    device: str = "/dev/ubertooth0"


@dataclass
class MonitoringConfig:
    """SentryWeb monitoring configuration."""

    alert_on_rogue_ap: bool = True
    alert_on_new_client: bool = False
    known_aps_file: str = ""
    poll_interval: float = 5.0


@dataclass
class CellularConfig:
    """CellGuard cellular scanning configuration."""

    enabled: bool = False
    rtlsdr_device: int = 0
    hackrf_device: str = ""
    scan_gsm: bool = True
    scan_lte: bool = True
    scan_5g: bool = False
    gsm_bands: list[str] = field(default_factory=lambda: ["GSM900", "GSM1800"])
    lte_bands: list[int] = field(default_factory=lambda: [2, 4, 5, 7, 12, 13, 66, 71])
    scan_interval: float = 30.0
    baseline_file: str = ""


@dataclass
class GuiConfig:
    """GUI configuration."""

    theme: str = "dark"
    map_tile_server: str = "OpenStreetMap"
    refresh_interval_ms: int = 1000
    max_devices_displayed: int = 500


@dataclass
class SecurityConfig:
    """Security, encryption, and audit configuration."""

    audit_enabled: bool = True
    audit_file: str = ""  # Defaults to <data_dir>/audit.jsonl
    encrypt_exports: bool = False
    encrypt_database: bool = False


@dataclass
class AppConfig:
    """Top-level application configuration."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    gps: GpsConfig = field(default_factory=GpsConfig)
    bluetooth: BluetoothConfig = field(default_factory=BluetoothConfig)
    cellular: CellularConfig = field(default_factory=CellularConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    gui: GuiConfig = field(default_factory=GuiConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    data_dir: str = str(DEFAULT_DATA_DIR)
    log_level: str = "INFO"
    oui_db_path: str = ""


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file, falling back to defaults."""
    config = AppConfig()

    if config_path is None:
        config_path = str(DEFAULT_CONFIG_DIR / "config.yaml")

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        _apply_dict(config, raw)

    # Ensure directories exist
    Path(config.data_dir).mkdir(parents=True, exist_ok=True)

    return config


def save_config(config: AppConfig, config_path: Optional[str] = None) -> None:
    """Save configuration to YAML file."""
    if config_path is None:
        config_path = str(DEFAULT_CONFIG_DIR / "config.yaml")

    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = _to_dict(config)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _apply_dict(obj: Any, data: dict) -> None:
    """Recursively apply dictionary values to a dataclass instance."""
    for key, value in data.items():
        if hasattr(obj, key):
            attr = getattr(obj, key)
            if isinstance(value, dict) and hasattr(attr, "__dataclass_fields__"):
                _apply_dict(attr, value)
            else:
                setattr(obj, key, value)


def _to_dict(obj: Any) -> dict:
    """Convert a dataclass to a dictionary recursively."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in obj.__dict__.items()}
    elif isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    return obj
