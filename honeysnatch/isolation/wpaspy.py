"""Wrapper for importing the wpaspy module from the vendor directory.

The wpaspy module provides a Python binding to the wpa_supplicant/hostapd
control interface. It is shipped in vendor/wpaspy.py as part of the
bundled hostap dependencies.

DL-01 (v0.1.7): the loader path passed to
`importlib.util.spec_from_file_location` is textually anchored at
`Path(__file__)` at every call site — no intermediate variable, no
loop binding, no env-var or config lookup. This is verified by the
static test in `tests/test_no_dynamic_code_loading.py::
test_wpaspy_loader_path_is_package_anchored`. If a future refactor
introduces an intermediate binding, do it in a way that keeps the
path expression at the loader call still rooted at `__file__` — or
update THREAT_MODEL.md to declare a broader loader surface first.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _try_load(parents_up: int):
    """Load wpaspy from a specific `parents[N]/vendor/...` location.

    The `spec_from_file_location` path argument is expressed inline as
    a Path(__file__)-rooted expression so a static reviewer (and the
    DL-01 regression test) can verify at read time that the loaded
    file is fixed by the installed package's own location.
    """
    if parents_up == 2:
        candidate = (
            Path(__file__).resolve().parents[2]
            / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py"
        )
        if not candidate.exists():
            return None
        spec = importlib.util.spec_from_file_location(
            "_vendor_wpaspy",
            str(
                Path(__file__).resolve().parents[2]
                / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py"
            ),
        )
    elif parents_up == 3:
        candidate = (
            Path(__file__).resolve().parents[3]
            / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py"
        )
        if not candidate.exists():
            return None
        spec = importlib.util.spec_from_file_location(
            "_vendor_wpaspy",
            str(
                Path(__file__).resolve().parents[3]
                / "vendor" / "hostap_2_10" / "wpaspy" / "wpaspy.py"
            ),
        )
    else:
        raise ValueError(f"unsupported parents_up depth {parents_up!r}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_vendor_wpaspy():
    """Load wpaspy Ctrl class from the vendor directory."""
    for depth in (2, 3):
        module = _try_load(depth)
        if module is not None:
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
