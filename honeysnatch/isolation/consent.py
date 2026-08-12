"""Consent gate for live isolation attacks (review finding F-04).

The AirSnitch-derived isolation tests actively probe target networks —
they associate as a client, send crafted frames, and observe reactions.
Pointed at a network the operator doesn't own or lack authorization to
test, they range from "annoying" to "computer misuse". SECURITY.md's
"Responsible Use" paragraph is not a technical control.

This module IS the technical control: every live isolation command must
present either a `--i-have-permission-to-attack <BSSID>` acknowledgment
or a stored consent token bound to the specific BSSID. Every grant lands
in the audit log so a downstream reviewer can prove that the operator
who ran the test also asserted authorization.

`--simulate` mode bypasses the gate but logs its own audit entry, so
the audit trail always distinguishes real on-air runs from dry-runs.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from honeysnatch.utils.logger import get_logger

log = get_logger("consent")


BSSID_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


class ConsentRequiredError(RuntimeError):
    """Raised when a live isolation command runs without operator consent."""


class BadBssidError(ValueError):
    """Raised when a BSSID string doesn't parse as a MAC address."""


# HS-02R remediation (v0.1.4 revision): consent capability is now
# strictly caused by a successful require_consent() call.
#
# The v0.1.3 attempt was theater: `Authorization.from_cli_ack(bssid)`
# minted its own receipt, so a hostile caller could produce a valid
# capability without ever running require_consent(). The v0.1.4 design
# inverts the control flow:
#
#   1. require_consent() is the SOLE mint point. It records the audit
#      event AND returns a `ConsentReceipt` (opaque, single-use) that
#      is registered in the process-local `_LIVE_RECEIPTS` map.
#   2. `Authorization.from_cli_ack(bssid, receipt)` requires the
#      receipt. Passing a made-up receipt or a receipt for a different
#      BSSID raises.
#   3. Each receipt is consumed on first use (single-use), so passing
#      a receipt to two Authorizations fails the second.
#   4. Direct construction of Authorization with a fake receipt_hash
#      still fails is_valid() (belt-and-braces from v0.1.3).

import hashlib
import secrets as _secrets
from typing import Dict as _Dict

# Every receipt minted by require_consent is registered here with the
# BSSID it was scoped to. Consumed on use — the entry is deleted when
# an Authorization is constructed with it. Prevents receipt reuse and
# prevents forgery: a hash that isn't in this map at construction time
# refuses to build an Authorization.
_LIVE_RECEIPTS: _Dict[str, str] = {}  # hash -> canonical bssid


@dataclass(frozen=True)
class ConsentReceipt:
    """Opaque single-use capability returned by require_consent().

    The plaintext receipt travels only far enough to be passed straight
    into `Authorization.from_cli_ack(bssid, receipt)` or
    `.from_token(bssid, receipt)`. Callers that log or persist the
    plaintext value are defeating the point.

    AUTH-01 (v0.1.5): `source` carries which consent path minted this
    receipt — CLI acknowledgment or persistent token. from_cli_ack
    refuses a token receipt and vice versa, so the audit record's
    consent form always matches the runtime capability's enforcement
    behaviour (token receipts trigger the mid-battery revalidation
    path in Authorization.is_valid()).
    """

    bssid: str          # canonical
    plaintext: str      # secrets.token_urlsafe(32)
    source: str         # "cli-ack" | "token"

    @property
    def receipt_hash(self) -> str:
        return hashlib.sha256(self.plaintext.encode("utf-8")).hexdigest()


def _mint_receipt(canonical_bssid: str, source: str) -> ConsentReceipt:
    """Mint a fresh single-use receipt scoped to `canonical_bssid`.

    Called ONLY by require_consent (in-module — the underscore prefix
    signals that). Registers the hash so Authorization.from_cli_ack /
    from_token will accept it exactly once.
    """
    assert source in ("cli-ack", "token"), f"bad receipt source {source!r}"
    receipt = ConsentReceipt(
        bssid=canonical_bssid,
        plaintext=_secrets.token_urlsafe(32),
        source=source,
    )
    _LIVE_RECEIPTS[receipt.receipt_hash] = canonical_bssid
    return receipt


def _consume_receipt(receipt_hash: str, expected_bssid: str) -> bool:
    """Consume a receipt if it exists and matches the expected BSSID.

    Returns True on success (the entry is removed). False on missing
    receipt or BSSID mismatch — the entry stays in place so a caller
    can't grief legitimate consent by passing a wrong-BSSID guess.
    """
    scoped_bssid = _LIVE_RECEIPTS.get(receipt_hash)
    if scoped_bssid is None:
        return False
    if scoped_bssid != expected_bssid:
        return False
    del _LIVE_RECEIPTS[receipt_hash]
    return True


# HS-02R (v0.1.5 revision): authorization proof lives OUTSIDE the object.
# The v0.1.4 attempt kept `_authenticated` as a dataclass field, which is
# a public constructor parameter no matter what leading-underscore
# convention says — a caller could pass _authenticated=True and get a
# valid capability. The reviewer's exact probe hit this.
#
# The v0.1.5 design moves the proof to a module-private WeakSet:
# `_AUTHENTIC_AUTHORIZATIONS`. Only the factory methods (which have
# consumed a valid receipt) add the constructed object to this set.
# `is_valid()` checks `self in _AUTHENTIC_AUTHORIZATIONS`. A caller who
# constructs an Authorization by any other means — regardless of what
# fields they pass — CANNOT get into that set.
#
# WeakSet so the entries are garbage-collected when the Authorization
# instance goes out of scope; per-process residue is bounded by live
# runner instances.
#
# TB-01 (v0.1.6 threat-model declaration): this WeakSet is a module
# global. Any Python code executing in the same interpreter can
# `import honeysnatch.isolation.consent` and call
# `consent._AUTHENTIC_AUTHORIZATIONS.add(forged)` to bypass the gate
# entirely. The underscore prefix is a naming convention, not an
# access boundary. THAT IS NOT A DEFENDED THREAT. See THREAT_MODEL.md:
# HoneySnatch v0.1.6 operates under a trusted-process boundary. The
# consent gate defends against operator mistakes, CLI accidents,
# cross-attack drift, token revocation, and audit tampering — NOT
# against hostile code with equivalent interpreter access. If your
# deployment includes untrusted in-process code, use OS-level
# isolation (separate user, MAC profile) or wait for the v0.2 broker
# refactor tracked as TB-01 Option B.

import weakref
_AUTHENTIC_AUTHORIZATIONS: "weakref.WeakSet[Authorization]" = weakref.WeakSet()


@dataclass(frozen=True, eq=False)
class Authorization:
    """A capability object attached to :class:`IsolationTestRunner`.

    HS-02R (v0.1.5): the sole test in `is_valid()` is IDENTITY-based
    membership in the module-private `_AUTHENTIC_AUTHORIZATIONS`
    weakset. `eq=False` on the dataclass keeps object.__hash__ /
    object.__eq__ (identity semantics) — so a clone with identical
    field values (e.g. an attacker copying receipt_hash from a leaked
    log) cannot pass `self in _AUTHENTIC_AUTHORIZATIONS` because it
    is a different object.

    Direct construction — `Authorization(bssid, source, hash)` — never
    inserts into the set, and identity-based membership means field
    replay attacks don't work either.

    TB-01 (v0.1.6): this defense is against ACCIDENTAL construction,
    field replay from leaked receipt hashes, and CLI/GUI code paths
    that forgot to call require_consent(). It is NOT a defense against
    hostile Python code executing in the same process — such code can
    reach into `_AUTHENTIC_AUTHORIZATIONS` and add a forged instance
    directly. See THREAT_MODEL.md for the deployment prerequisites
    that make this boundary meaningful and for the mitigations that
    apply when it doesn't hold.
    """

    bssid: str
    source: str          # "cli-ack" | "token"
    receipt_hash: str

    @classmethod
    def from_cli_ack(cls, bssid: str, receipt: ConsentReceipt) -> "Authorization":
        """Construct an Authorization from a CLI-ack receipt.

        HS-02S (v0.1.5): the source stays "cli-ack" here because the
        receipt was minted by the CLI-ack path in require_consent.
        """
        canonical = canonicalize_bssid(bssid)
        if not isinstance(receipt, ConsentReceipt):
            raise ConsentRequiredError(
                "from_cli_ack requires a ConsentReceipt returned by "
                "require_consent(). Got: " + type(receipt).__name__
            )
        if receipt.source != "cli-ack":
            raise ConsentRequiredError(
                f"Receipt source is {receipt.source!r}; use from_token() "
                "for token-derived receipts (AUTH-01 remediation)."
            )
        if not _consume_receipt(receipt.receipt_hash, canonical):
            raise ConsentRequiredError(
                "Consent receipt is invalid, expired, or already consumed. "
                "Run require_consent() again and pass its return value here."
            )
        instance = cls(
            bssid=canonical,
            source="cli-ack",
            receipt_hash=receipt.receipt_hash,
        )
        _AUTHENTIC_AUTHORIZATIONS.add(instance)
        return instance

    @classmethod
    def from_token(cls, bssid: str, receipt: ConsentReceipt) -> "Authorization":
        """Construct an Authorization from a persistent-token receipt.

        AUTH-01: the receipt's `source` MUST be "token"; a cli-ack
        receipt cannot be laundered through this factory.
        """
        canonical = canonicalize_bssid(bssid)
        if not isinstance(receipt, ConsentReceipt):
            raise ConsentRequiredError(
                "from_token requires a ConsentReceipt returned by "
                "require_consent(). Got: " + type(receipt).__name__
            )
        if receipt.source != "token":
            raise ConsentRequiredError(
                f"Receipt source is {receipt.source!r}; use from_cli_ack() "
                "for CLI-acknowledgment receipts (AUTH-01 remediation)."
            )
        if not _consume_receipt(receipt.receipt_hash, canonical):
            raise ConsentRequiredError(
                "Consent receipt is invalid, expired, or already consumed."
            )
        instance = cls(
            bssid=canonical,
            source="token",
            receipt_hash=receipt.receipt_hash,
        )
        _AUTHENTIC_AUTHORIZATIONS.add(instance)
        return instance

    def is_valid(self) -> bool:
        """Runner-side check called by every `run_*` method.

        HS-02R (v0.1.5): membership in _AUTHENTIC_AUTHORIZATIONS is
        the ONLY thing that matters. Direct construction — with ANY
        field values, including a real receipt_hash copied from a
        legitimate object — cannot get into the set.
        """
        if self not in _AUTHENTIC_AUTHORIZATIONS:
            return False
        # AUTH-01: token-backed authorizations recheck the on-disk token
        # each gate check, so an operator revoking or letting a token
        # expire mid-battery stops further live methods.
        if self.source == "token":
            tok = load_consent(self.bssid)
            return tok is not None and tok.is_valid_for(self.bssid)
        return True

    def matches_observed_bssid(self, observed_bssid: str) -> bool:
        """Compare authorization's BSSID to what wpa_supplicant reports."""
        try:
            return canonicalize_bssid(observed_bssid) == self.bssid
        except BadBssidError:
            return False


@dataclass
class ConsentToken:
    """A single consent record.

    `bssid` is canonicalized to lowercase colon-separated form.
    `expires_at` is a UTC ISO-8601 timestamp; the gate compares against
    `datetime.now(timezone.utc)`.
    """

    bssid: str
    granted_at: str
    expires_at: str
    granted_by: str        # <user>@<host>
    reason: str = ""

    def is_valid_for(self, bssid: str, now: Optional[datetime] = None) -> bool:
        if now is None:
            now = datetime.now(timezone.utc)
        if canonicalize_bssid(bssid) != self.bssid:
            return False
        try:
            expires = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        return now < expires


def canonicalize_bssid(bssid: str) -> str:
    """Normalize a BSSID to lowercase colon-separated form. Raises on bad input."""
    if not isinstance(bssid, str) or not BSSID_RE.match(bssid.strip()):
        raise BadBssidError(
            f"expected a MAC address like aa:bb:cc:dd:ee:ff, got {bssid!r}"
        )
    return bssid.strip().lower()


def _default_store_dir() -> Path:
    """Where consent tokens live on disk."""
    override = os.environ.get("FHS_CONSENT_DIR")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "honeysnatch" / "consent"


def _who() -> str:
    """Best-effort operator identity for audit-log attribution."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown-host"
    return f"{user}@{host}"


def grant_consent(
    bssid: str,
    window_minutes: int = 60,
    reason: str = "",
    store_dir: Optional[Path] = None,
) -> ConsentToken:
    """Create and persist a consent token for `bssid`.

    Returns the ConsentToken so callers can log it. Persisted file is
    JSON, mode 0600, named `<bssid>.json` under the consent dir.
    """
    canonical = canonicalize_bssid(bssid)
    if window_minutes < 1 or window_minutes > 24 * 60:
        raise ValueError(
            f"window_minutes must be between 1 and 1440 (got {window_minutes})"
        )

    now = datetime.now(timezone.utc)
    token = ConsentToken(
        bssid=canonical,
        granted_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=window_minutes)).isoformat(),
        granted_by=_who(),
        reason=reason.strip(),
    )

    dest_dir = store_dir or _default_store_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)

    # BSSID is safe as a filename (regex-validated), but scrub colons for
    # Windows filesystems just in case someone runs this cross-platform.
    dest = dest_dir / f"{canonical.replace(':', '')}.json"
    payload = json.dumps(token.__dict__, indent=2)

    # Write with 0600 from the start — no permission race.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)

    return token


def load_consent(
    bssid: str,
    store_dir: Optional[Path] = None,
) -> Optional[ConsentToken]:
    """Load the consent token for `bssid`, or None if absent/malformed."""
    canonical = canonicalize_bssid(bssid)
    dest_dir = store_dir or _default_store_dir()
    src = dest_dir / f"{canonical.replace(':', '')}.json"
    if not src.exists():
        return None
    try:
        raw = json.loads(src.read_text())
        return ConsentToken(**raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        log.warning("Consent file %s is malformed; ignoring", src)
        return None


def _record_or_fail(audit_logger, event, data):
    """Record a security-critical audit event; raise if audit isn't
    durable. Consent acks and token uses ARE the operator-visible
    evidence that authorized a live attack — losing them silently
    breaks the tamper-evidence contract SECURITY.md advertises.

    Non-security calls (denials, simulate runs) stay best-effort so a
    broken audit log doesn't prevent operators from seeing that a
    refusal happened.
    """
    try:
        audit_logger.record(event, data)
    except Exception as exc:
        raise ConsentRequiredError(
            f"Consent refused: audit event {event!r} could not be recorded "
            f"({exc}). Live isolation requires a durable audit trail."
        ) from exc


def require_consent(
    bssid: Optional[str],
    ack_bssid: Optional[str],
    simulate: bool,
    audit_logger=None,
    context: Optional[dict] = None,
) -> Optional[ConsentReceipt]:
    """Gate for every live isolation command.

    HS-02R (v0.1.4): this is now the SOLE mint point for consent
    capabilities. On successful non-simulate paths it returns a
    ConsentReceipt that the caller must pass into
    Authorization.from_cli_ack() / .from_token(). Simulate mode
    returns None (no capability needed).

    Args:
        bssid: The target BSSID the caller intends to attack. If None,
            no scope was specified and we refuse regardless.
        ack_bssid: Value of the CLI `--i-have-permission-to-attack` flag.
        simulate: If True, no on-air packets will be sent.
        audit_logger: Optional AuditLogger override.
        context: Structured context attached to the audit entry.

    Returns:
        ConsentReceipt on successful non-simulate paths;
        None in simulate mode.

    Raises:
        ConsentRequiredError: no valid consent for this run.
        BadBssidError: `bssid` is not a MAC address.
    """
    if audit_logger is None:
        from honeysnatch.utils.audit import get_audit_logger
        audit_logger = get_audit_logger()

    ctx = dict(context or {})
    who = _who()

    if simulate:
        audit_logger.record(
            "isolation_simulate_run",
            {"bssid": bssid, "operator": who, **ctx},
        )
        log.warning(
            "SIMULATE mode: no on-air packets will be sent; consent gate bypassed."
        )
        return None

    if not bssid:
        raise ConsentRequiredError(
            "Live isolation runs require an explicit --target-bssid so consent "
            "can be scoped. Pass --simulate for dry-run, or --target-bssid "
            "AA:BB:CC:DD:EE:FF plus --i-have-permission-to-attack AA:BB:CC:DD:EE:FF."
        )

    canonical = canonicalize_bssid(bssid)  # raises BadBssidError on bad input

    # Path 1: fresh CLI acknowledgment (--i-have-permission-to-attack).
    if ack_bssid:
        try:
            canonical_ack = canonicalize_bssid(ack_bssid)
        except BadBssidError as exc:
            raise ConsentRequiredError(
                f"--i-have-permission-to-attack value is not a BSSID: {exc}"
            ) from exc

        if canonical_ack != canonical:
            raise ConsentRequiredError(
                f"Acknowledgment BSSID {canonical_ack} does not match target "
                f"{canonical}. Consent must name the exact target."
            )

        _record_or_fail(
            audit_logger,
            "isolation_consent_ack",
            {
                "bssid": canonical,
                "operator": who,
                "form": "cli-flag",
                **ctx,
            },
        )
        return _mint_receipt(canonical, source="cli-ack")

    # Path 2: persisted consent token.
    token = load_consent(canonical)
    if token is not None and token.is_valid_for(canonical):
        _record_or_fail(
            audit_logger,
            "isolation_consent_token",
            {
                "bssid": canonical,
                "operator": who,
                "form": "token",
                "granted_by": token.granted_by,
                "granted_at": token.granted_at,
                "expires_at": token.expires_at,
                **ctx,
            },
        )
        return _mint_receipt(canonical, source="token")

    # Nothing valid — refuse and record the refusal.
    audit_logger.record(
        "isolation_consent_denied",
        {"bssid": canonical, "operator": who, **ctx},
    )
    raise ConsentRequiredError(
        f"Live isolation run against {canonical} refused: no valid consent. "
        "Either pass --i-have-permission-to-attack " + canonical + " on this "
        "invocation, or `fhs isolation consent grant " + canonical + "` first."
    )
