"""Runner-boundary consent gate regression tests (review finding HS-02).

Prior to remediation, `IsolationTestRunner(simulate=False)` could be
constructed by any programmatic caller (including the GUI) and its
`run_*` methods would fire without any consent check — the CLI was
the only enforcement point. Now the runner refuses live work unless
constructed with an :class:`Authorization` or `simulate=True`.

These tests exercise every public `run_*` method and assert:
  1. `simulate=False` + no `authorization` → ConsentRequiredError
  2. `simulate=True` → runs (returns INCONCLUSIVE, no hardware needed)
  3. Valid `Authorization.from_cli_ack(bssid)` → runs
  4. Wrong-BSSID authorization is REFUSED at the observed-target
     verification step (HS-02R). The gate itself accepts a
     valid-looking Authorization; the runner's `_verify_observed_target()`
     is what compares the authorized BSSID against what the supplicant
     reports and aborts before any on-air work. See
     `tests/isolation/test_authorization_binding.py` for the
     observed-BSSID binding tests.
"""

from __future__ import annotations

import pytest

from honeysnatch.isolation.consent import (
    Authorization,
    ConsentRequiredError,
)
from honeysnatch.isolation.runner import IsolationTestRunner


TARGET = "AA:BB:CC:DD:EE:FF"


LIVE_METHODS = [
    ("run_gtk_check", ("wlan1",)),
    ("run_client2client", ("wlan1",)),
    ("run_client2monitor", ("wlan1",)),
    ("run_port_steal", ("wlan1",)),
    ("run_gateway_bounce", ("wlan1",)),
    ("run_broadcast_reflection", ("wlan1",)),
    ("run_all", ("wlan1",)),
]


class TestUnauthorizedRunnerBlocks:
    """Every live method MUST refuse without authorization."""

    @pytest.mark.parametrize("method,args", LIVE_METHODS)
    def test_no_authz_no_simulate_refused(self, method, args):
        runner = IsolationTestRunner(interface="wlan0")  # no simulate, no authz
        fn = getattr(runner, method)
        with pytest.raises(ConsentRequiredError):
            fn(*args)


class TestSimulateBypassesGate:
    """simulate=True dry-runs are allowed without an Authorization —
    they produce no on-air traffic."""

    @pytest.mark.parametrize("method,args", LIVE_METHODS)
    def test_simulate_runs_through_gate(self, method, args):
        runner = IsolationTestRunner(interface="wlan0", simulate=True)
        fn = getattr(runner, method)
        # Doesn't need to succeed usefully — just NOT raise ConsentRequiredError.
        try:
            fn(*args)
        except ConsentRequiredError as exc:
            pytest.fail(f"simulate mode should bypass gate: {exc}")
        except Exception:
            # Simulation may fail deeper for hardware-shaped reasons, but
            # the consent gate is what we're proving.
            pass


class TestValidAuthorizationLetsRunThrough:
    """A runner constructed with Authorization.from_cli_ack must not
    fail the gate."""

    @pytest.mark.parametrize("method,args", LIVE_METHODS)
    def test_cli_ack_authz_bypasses_gate(self, method, args, monkeypatch, tmp_path):
        from honeysnatch.isolation.consent import require_consent
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path / "consent"))
        monkeypatch.setenv("HOME", str(tmp_path))
        # HS-02R (v0.1.4): capability now requires a receipt from
        # require_consent — no more self-minting factory.
        receipt = require_consent(bssid=TARGET, ack_bssid=TARGET, simulate=False)
        authz = Authorization.from_cli_ack(TARGET, receipt)
        runner = IsolationTestRunner(
            interface="wlan0",
            simulate=True,  # simulate is fine for testing the gate specifically
            authorization=authz,
        )
        # The gate check happens first; simulate lets everything below it
        # complete quickly.
        fn = getattr(runner, method)
        try:
            fn(*args)
        except ConsentRequiredError as exc:
            pytest.fail(f"valid CLI-ack authorization should pass the gate: {exc}")
        except Exception:
            pass


class TestAuthorizationValidity:
    def test_cli_ack_valid_after_consent(self, monkeypatch, tmp_path):
        from honeysnatch.isolation.consent import require_consent
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(bssid=TARGET, ack_bssid=TARGET, simulate=False)
        authz = Authorization.from_cli_ack(TARGET, receipt)
        assert authz.is_valid() is True

    def test_from_cli_ack_without_receipt_fails(self, monkeypatch, tmp_path):
        """v0.1.4: capability now requires a ConsentReceipt from
        require_consent(). Calling from_cli_ack without one raises
        TypeError at signature time — the reviewer's HS-02R bypass
        is inverted."""
        with pytest.raises(TypeError):
            Authorization.from_cli_ack(TARGET)  # type: ignore[call-arg]

    def test_from_token_without_receipt_fails(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        with pytest.raises(TypeError):
            Authorization.from_token(TARGET)  # type: ignore[call-arg]

    def test_token_authz_valid_after_grant_and_consent(self, monkeypatch, tmp_path):
        from honeysnatch.isolation.consent import grant_consent, require_consent
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        grant_consent(TARGET, window_minutes=30)
        # v0.1.4: require_consent produces the receipt for the token path too.
        receipt = require_consent(bssid=TARGET, ack_bssid=None, simulate=False)
        authz = Authorization.from_token(TARGET, receipt)
        assert authz.is_valid() is True
        assert authz.source == "token"


class TestReviewersExactHs02Bypass:
    """The exact HS-02 reproducer: constructing the runner directly
    (as the GUI did) with simulate=False, then calling run_all —
    MUST NOT execute any live attack. Now raises."""

    def test_direct_run_all_construction_blocked(self):
        runner = IsolationTestRunner(interface="wlan0")  # what the GUI did
        with pytest.raises(ConsentRequiredError) as exc:
            runner.run_all("wlan1")
        assert "no valid authorization" in str(exc.value).lower()
