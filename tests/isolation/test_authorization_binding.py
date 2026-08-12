"""HS-02R (v0.1.4) regression tests — capability is caused by consent.

v0.1.3 remediation attempt was theater: `Authorization.from_cli_ack`
minted its own receipt, so any caller could obtain a live capability
without ever running `require_consent`. This test suite proves the
v0.1.4 design where:

  - `require_consent()` is the SOLE mint point.
  - `Authorization.from_cli_ack(bssid, receipt)` REQUIRES the receipt.
  - The receipt is single-use and BSSID-scoped.
  - `_verify_observed_target(observed_bssid)` is called by every live
    method in the runner before any packet-side effects.
"""

from __future__ import annotations

import hashlib

import pytest

from honeysnatch.isolation.consent import (
    _AUTHENTIC_AUTHORIZATIONS,
    _LIVE_RECEIPTS,
    Authorization,
    ConsentReceipt,
    ConsentRequiredError,
    require_consent,
)
from honeysnatch.isolation.runner import IsolationTestRunner


TARGET = "AA:BB:CC:DD:EE:FF"
CANONICAL = "aa:bb:cc:dd:ee:ff"
OTHER = "11:22:33:44:55:66"


@pytest.fixture(autouse=True)
def _clean_receipt_store():
    """Clear the process-local receipt store around every test so
    cross-test pollution can't produce false positives."""
    _LIVE_RECEIPTS.clear()
    yield
    _LIVE_RECEIPTS.clear()


# ══════════════════════════════════════════════════════════════════════
# The exact reviewer HS-02R probe: from_cli_ack without require_consent
# ══════════════════════════════════════════════════════════════════════

class TestReviewersHs02rBypass:
    """The reviewer's exact probe: `from_cli_ack` called without
    `require_consent` — must NOT return a live capability."""

    def test_from_cli_ack_without_receipt_refuses(self):
        # No `receipt` argument — the old signature is gone.
        with pytest.raises(TypeError):
            Authorization.from_cli_ack(TARGET)  # type: ignore[call-arg]

    def test_from_cli_ack_with_fabricated_receipt_refuses(self):
        fake = ConsentReceipt(
            bssid=CANONICAL, plaintext="attacker-guessed", source="cli-ack",
        )
        with pytest.raises(ConsentRequiredError) as exc:
            Authorization.from_cli_ack(TARGET, fake)
        assert "invalid, expired, or already consumed" in str(exc.value).lower()

    def test_from_cli_ack_with_non_receipt_type_refuses(self):
        with pytest.raises(ConsentRequiredError):
            Authorization.from_cli_ack(TARGET, "just-a-string")  # type: ignore[arg-type]

    def test_from_token_without_receipt_refuses(self):
        with pytest.raises(TypeError):
            Authorization.from_token(TARGET)  # type: ignore[call-arg]


class TestDirectConstructionInert:
    """Direct dataclass construction (bypassing the factories) MUST
    NOT produce a valid authorization — under ANY field values.

    HS-02R (v0.1.5 revision): the reviewer's v0.1.4 probe passed
    `_authenticated=True` directly. That worked because the field was
    a public dataclass parameter. Now proof lives OUTSIDE the object
    in a module-private WeakSet, so no combination of constructor
    arguments can produce a valid authorization.
    """

    def test_direct_construction_with_zero_hash(self):
        fake = Authorization(bssid=CANONICAL, source="cli-ack",
                             receipt_hash="0" * 64)
        assert fake.is_valid() is False

    def test_direct_construction_with_random_hash(self):
        import secrets as _s
        fake = Authorization(
            bssid=CANONICAL, source="cli-ack",
            receipt_hash=hashlib.sha256(_s.token_bytes(32)).hexdigest(),
        )
        assert fake.is_valid() is False

    def test_reviewer_hs02r_v014_forgery_probe_refused(self):
        """The reviewer's EXACT v0.1.4 probe: pass fields that mimic a
        legitimate authorization, including an attacker-friendly
        receipt_hash. Pre-v0.1.5, this returned is_valid=True. Now:
        `_AUTHENTIC_AUTHORIZATIONS` membership is the sole test, and
        direct construction never gets into that set."""
        forged = Authorization(
            bssid=CANONICAL, source="cli-ack", receipt_hash="attacker",
        )
        assert forged.is_valid() is False, (
            "HS-02R (v0.1.5) regression: reviewer's direct-construction "
            "forgery probe accepted"
        )

    def test_authenticated_kwarg_no_longer_exists(self):
        """The `_authenticated` field is gone from the constructor —
        passing it raises TypeError, so a future refactor that
        reintroduces it as a public field will fail this test loudly."""
        with pytest.raises(TypeError):
            Authorization(
                bssid=CANONICAL, source="cli-ack",
                receipt_hash="x", _authenticated=True,  # type: ignore[call-arg]
            )

    def test_copying_a_real_authorization_receipt_hash_still_refused(self, tmp_path, monkeypatch):
        """An attacker who observes a REAL Authorization's receipt_hash
        (via debugger, logs, whatever) and constructs a lookalike must
        STILL be refused — because membership in the WeakSet is by
        object identity, not by field values."""
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        real = Authorization.from_cli_ack(
            TARGET,
            require_consent(bssid=TARGET, ack_bssid=TARGET, simulate=False),
        )
        assert real.is_valid() is True
        clone = Authorization(
            bssid=real.bssid, source=real.source, receipt_hash=real.receipt_hash,
        )
        assert clone.is_valid() is False, (
            "HS-02R regression: an Authorization built from copied field "
            "values must not authenticate; the WeakSet is identity-based"
        )


# ══════════════════════════════════════════════════════════════════════
# The correct path — require_consent → receipt → from_cli_ack
# ══════════════════════════════════════════════════════════════════════

class TestLegitimateFlow:
    def test_require_consent_returns_receipt(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(
            bssid=TARGET, ack_bssid=TARGET, simulate=False,
        )
        assert isinstance(receipt, ConsentReceipt)
        assert receipt.bssid == CANONICAL
        # The receipt is registered.
        assert receipt.receipt_hash in _LIVE_RECEIPTS

    def test_receipt_scoped_bssid_matches_target(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(
            bssid=TARGET, ack_bssid=TARGET, simulate=False,
        )
        # Cross-BSSID from_cli_ack must refuse: the receipt is scoped
        # to TARGET, not OTHER.
        with pytest.raises(ConsentRequiredError):
            Authorization.from_cli_ack(OTHER, receipt)

    def test_receipt_single_use(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(
            bssid=TARGET, ack_bssid=TARGET, simulate=False,
        )
        authz = Authorization.from_cli_ack(TARGET, receipt)
        assert authz.is_valid()
        # Second use of the same receipt must fail — it was consumed.
        with pytest.raises(ConsentRequiredError) as exc:
            Authorization.from_cli_ack(TARGET, receipt)
        assert "consumed" in str(exc.value).lower() or "invalid" in str(exc.value).lower()

    def test_simulate_returns_no_receipt(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        # simulate=True short-circuits and returns None.
        result = require_consent(
            bssid=None, ack_bssid=None, simulate=True,
        )
        assert result is None


# ══════════════════════════════════════════════════════════════════════
# Runner enforcement — every live method verifies the observed BSSID
# ══════════════════════════════════════════════════════════════════════

class TestRunnerVerifiesObservedBssid:
    """The reviewer's second complaint: `_verify_observed_target`
    existed but no `_*_live` method called it. Static assertion +
    behavioural assertion."""

    def test_all_live_methods_reference_verify(self):
        """Static: every `_*_live` method's source contains a call to
        `self._verify_observed_target(...)`. Prevents a future refactor
        from silently removing the enforcement."""
        import inspect
        from honeysnatch.isolation import runner as runner_mod

        live_methods = [
            name for name in dir(runner_mod.IsolationTestRunner)
            if name.endswith("_live") and name.startswith("_")
        ]
        assert len(live_methods) >= 6, \
            f"expected ≥6 live methods, found {len(live_methods)}: {live_methods}"

        missing = []
        for name in live_methods:
            fn = getattr(runner_mod.IsolationTestRunner, name)
            source = inspect.getsource(fn)
            if "self._verify_observed_target(" not in source:
                missing.append(name)
        assert not missing, (
            f"HS-02R regression: live methods missing verify: {missing}. "
            "Add self._verify_observed_target(info.bssid, ...) right "
            "after supplicant association."
        )

    def _authorized_runner(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(
            bssid=TARGET, ack_bssid=TARGET, simulate=False,
        )
        authz = Authorization.from_cli_ack(TARGET, receipt)
        return IsolationTestRunner(
            interface="wlan0", simulate=False, authorization=authz,
        )

    def test_verify_match_permits(self, tmp_path, monkeypatch):
        r = self._authorized_runner(tmp_path, monkeypatch)
        r._verify_observed_target(TARGET, attack_label="test")  # no raise

    def test_verify_mismatch_refuses(self, tmp_path, monkeypatch):
        r = self._authorized_runner(tmp_path, monkeypatch)
        with pytest.raises(ConsentRequiredError) as exc:
            r._verify_observed_target(OTHER, attack_label="c2c-ip")
        assert "no attack packets" in str(exc.value).lower()

    def test_verify_mismatch_records_audit_event(self, tmp_path, monkeypatch):
        r = self._authorized_runner(tmp_path, monkeypatch)
        with pytest.raises(ConsentRequiredError):
            r._verify_observed_target(OTHER, attack_label="c2c-ip")
        audit_log = tmp_path / ".local" / "share" / "honeysnatch" / "audit.jsonl"
        assert audit_log.exists()
        assert "isolation_bssid_mismatch" in audit_log.read_text()


# ══════════════════════════════════════════════════════════════════════
# End-to-end: patch on-air functions, prove they don't run on bypass
# ══════════════════════════════════════════════════════════════════════

class TestSecondaryBssidVerification:
    """HS-02S (v0.1.5): the five two-interface attacks call
    start_and_connect() TWICE — once on the victim/primary interface,
    once on the attacker/secondary interface. Pre-v0.1.5 only the
    primary result was verified; the attacker interface could be
    associated to a different network entirely. Now both results are
    checked, and the runner requires them to match the authorized
    target."""

    TWO_IFACE_METHODS = [
        "_gtk_check_live",
        "_c2c_live",
        "_port_steal_live",
        "_gw_bounce_live",
        "_broadcast_reflection_live",
    ]

    def test_every_two_iface_method_verifies_both_associations(self):
        """Static: every two-interface `_*_live` method calls
        `_verify_observed_target` at least TWICE — once per
        associated interface."""
        import inspect
        from honeysnatch.isolation.runner import IsolationTestRunner

        under_verified = []
        for name in self.TWO_IFACE_METHODS:
            fn = getattr(IsolationTestRunner, name)
            source = inspect.getsource(fn)
            n_assoc = source.count(".start_and_connect(")
            n_verify = source.count("self._verify_observed_target(")
            if n_verify < n_assoc:
                under_verified.append(
                    f"{name}: {n_assoc} associations, only {n_verify} verifications"
                )

        assert not under_verified, (
            "HS-02S regression: two-interface methods with unverified "
            "secondary associations:\n  " + "\n  ".join(under_verified)
        )

    def test_verify_call_immediately_follows_each_association(self):
        """Order matters: the verify MUST come right after the
        start_and_connect it's checking, before any downstream code
        uses the returned info object."""
        import inspect, re
        from honeysnatch.isolation.runner import IsolationTestRunner

        offenders = []
        for name in self.TWO_IFACE_METHODS:
            fn = getattr(IsolationTestRunner, name)
            source = inspect.getsource(fn)
            # Every `info<x> = sup<y>.start_and_connect()` should be
            # immediately followed by a line calling
            # self._verify_observed_target(info<x>.bssid, ...).
            for m in re.finditer(
                r"(\s+)(info\w*) = sup\w+\.start_and_connect\(\)\n(\1)([^\n]+)\n",
                source,
            ):
                indent, varname, next_indent, next_line = m.groups()
                verify_expected = f"self._verify_observed_target({varname}.bssid"
                if verify_expected not in next_line:
                    offenders.append(
                        f"{name}: {varname} assoc not immediately followed by verify — next line: {next_line.strip()!r}"
                    )
        assert not offenders, (
            "HS-02S regression: verify doesn't immediately follow "
            "start_and_connect:\n  " + "\n  ".join(offenders)
        )


class TestReceiptSourceAndAuth01:
    """AUTH-01: receipt carries `source`, and each factory refuses a
    receipt of the wrong source. Token-derived receipts flow into
    from_token, which triggers the token-revalidation branch in
    is_valid()."""

    def test_cli_ack_receipt_refused_by_from_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        receipt = require_consent(
            bssid=TARGET, ack_bssid=TARGET, simulate=False,
        )
        assert receipt.source == "cli-ack"
        with pytest.raises(ConsentRequiredError) as exc:
            Authorization.from_token(TARGET, receipt)
        assert "source" in str(exc.value).lower() or "auth-01" in str(exc.value).lower()

    def test_token_receipt_refused_by_from_cli_ack(self, tmp_path, monkeypatch):
        from honeysnatch.isolation.consent import grant_consent
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        grant_consent(TARGET, window_minutes=30)
        receipt = require_consent(
            bssid=TARGET, ack_bssid=None, simulate=False,
        )
        assert receipt.source == "token"
        with pytest.raises(ConsentRequiredError):
            Authorization.from_cli_ack(TARGET, receipt)

    def test_revoked_token_disables_authorization_mid_lifetime(self, tmp_path, monkeypatch):
        """AUTH-01: an authorized runner backed by a token loses
        authorization when the operator revokes the token — the
        is_valid() check reloads on every call."""
        from honeysnatch.isolation.consent import (
            _default_store_dir, grant_consent,
        )
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))
        grant_consent(TARGET, window_minutes=30)
        receipt = require_consent(
            bssid=TARGET, ack_bssid=None, simulate=False,
        )
        authz = Authorization.from_token(TARGET, receipt)
        assert authz.is_valid() is True

        # Operator revokes the token mid-battery.
        for f in _default_store_dir().glob("*.json"):
            f.unlink()
        assert authz.is_valid() is False, (
            "AUTH-01 regression: token-backed authz still valid after "
            "revocation"
        )


class TestNoPacketsOnBypass:
    """The reviewer's acceptance criterion for HS-02R: patch send/
    sniff/probe/key-extraction, then attempt bypasses, and prove none
    of those functions were called.

    We simulate a fabricated authorization at the runner level and
    invoke run_gtk_check(); the gate must refuse before any of the
    patched functions get called.
    """

    def test_run_all_refuses_forged_authz_before_any_side_effect(self):
        """Runner constructed with a made-up Authorization must refuse
        before any subprocess/scapy/send code is reached."""
        forged = Authorization(
            bssid=CANONICAL, source="cli-ack",
            receipt_hash="deadbeef" * 8,  # not in _LIVE_RECEIPTS
        )
        runner = IsolationTestRunner(
            interface="wlan0", simulate=False, authorization=forged,
        )
        # Attempt the full battery — every entry point must refuse.
        for method_name in (
            "run_gtk_check", "run_client2client", "run_client2monitor",
            "run_port_steal", "run_gateway_bounce",
            "run_broadcast_reflection", "run_all",
        ):
            fn = getattr(runner, method_name)
            with pytest.raises(ConsentRequiredError):
                fn("wlan1")
