"""Wrapper for importing the wpaspy module from the vendor directory.

The wpaspy module provides a Python binding to the wpa_supplicant/hostapd
control interface. It is shipped in vendor/wpaspy.py as part of the
bundled hostap dependencies.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_vendor_wpaspy():
    """Load wpaspy Ctrl class from the vendor directory."""
    # Try vendor/ relative to the project root (3 levels up from this file)
    candidates = [
        Path(__file__).resolve().parents[2] / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py",
        Path(__file__).resolve().parents[3] / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py",
    ]
    for vendor_path in candidates:
        if vendor_path.exists():
            spec = importlib.util.spec_from_file_location("_vendor_wpaspy", str(vendor_path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

    raise ImportError(
        "wpaspy.py not found in vendor directory. "
        "Run vendor/build.sh to compile hostap dependencies, or ensure the "
        "vendor/hostap_2_10/wpaspy/wpaspy.py file exists."
    )


try:
    _wpaspy = _load_vendor_wpaspy()
    Ctrl = _wpaspy.Ctrl
except ImportError:
    # Allow the package to be imported on non-Linux systems for testing
    Ctrl = None
