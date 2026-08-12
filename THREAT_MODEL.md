# HoneySnatch Threat Model

**Version:** 0.1.10
**Status:** Trusted-process boundary declared (TB-01, v0.1.5 follow-up review)
**Companion:** `SECURITY.md`

## Purpose

This document names what HoneySnatch's in-process controls do and do not
defend against. It exists because the v0.1.5 follow-up review flagged
TB-01: the consent-gate implementation stores authorization proof in a
module-private `WeakSet` (`consent._AUTHENTIC_AUTHORIZATIONS`) that any
same-process Python caller can mutate directly. Underscore prefixes,
frozen dataclasses, and `WeakSet` identity semantics are Python
conventions, not security boundaries against code executing inside the
same interpreter.

Rather than pretend otherwise, this document narrows the threat model.
Everything the consent gate claims is claimed *under this model*.

## In-scope threats

The consent gate, target-BSSID binding, receipt source discipline,
full-chain audit HMAC, and fail-closed encrypted-DB integration ARE
designed to defend against:

1. **Operator mistakes.** An operator who runs `fhs isolation run-c2c
   --target-bssid AA:BB:CC:DD:EE:FF` but forgets the acknowledgment
   flag, or who acknowledges the wrong BSSID, is refused before any
   packet leaves the radio.
2. **Command-line accidents.** Copy-paste of a stale command, a shell
   history that grabs the wrong BSSID, a scripted battery that lost
   its target-scope flag. All refused; refusal is audited.
3. **Cross-attack drift within a battery.** Once wpa_supplicant
   associates, the observed BSSID is compared to the authorized one on
   every attack site (primary AND secondary supplicants). A misconfig
   that lands the second radio on the wrong network stops the attack
   before frames are emitted.
4. **Token expiry / revocation mid-run.** A persistent consent token
   that expires or is deleted between attacks invalidates the
   authorization at the next gate check. Token receipts re-read the
   on-disk token every `is_valid()` call.
5. **Audit-log tampering.** The audit chain is HMAC-linked; any edit
   or truncation trips full-chain verification on the next init.
   Encrypted-DB opens FAIL CLOSED on audit failure.
6. **Filesystem containment.** `_safe_rmtree` refuses paths outside
   the allowlisted control roots (`/run/hostapd`, `/run/wpa_supplicant`,
   etc.) and refuses to traverse symlinks. A hostile arg won't wipe
   `/etc`.

## Out-of-scope threats (documented, not defended)

The following are OUT OF SCOPE. HoneySnatch does not claim to defeat
them. An operator who deploys HoneySnatch in a context where these
threats are live must supply the boundary elsewhere (OS user account
separation, container isolation, mandatory access control, or the
Option B broker architecture sketched at the end of this document).

### TB-01: Hostile Python code executing inside the HoneySnatch process

Any code with equivalent interpreter access — an imported third-party
module, a pickle-deserialized payload, a compromised dependency, code
injected via `exec()`, an interactive REPL attached to the running
process — can:

- Import `honeysnatch.isolation.consent` and mutate
  `_AUTHENTIC_AUTHORIZATIONS` directly.
- Construct an `Authorization(bssid, source, receipt_hash)` and add it
  to the set: `consent._AUTHENTIC_AUTHORIZATIONS.add(forged)`.
- Cause `is_valid()` to return `True` and reach live radio dispatch
  without ever calling `require_consent()`, without a receipt, and
  without an authorization audit event.

This is not a HoneySnatch defect. It is a consequence of Python's
execution model: a module-private name is a naming convention, not an
access boundary. `frozen=True` on a dataclass prevents attribute
assignment, not module-global reassignment. `WeakSet` identity
semantics prevent field-replay clones from being accepted, but do
nothing against a caller who inserts the real forged object into the
registry itself.

**The consent gate is designed to prevent misuse, not to sandbox
malicious in-process code.** If arbitrary in-process code is untrusted
in your deployment, use the mitigations at the end of this document
instead of expecting the consent gate to protect you.

### HS-06: Local privilege escalation via the Python interpreter

`fhs` runs under a group whose members already have raw-socket and
capture privileges granted by capability elevation on the wheel-shipped
`fhs` binary or by group membership in the deploy scripts. Anyone in
that group can also run `python3` directly and construct raw packets
themselves. The consent gate does not limit what a Python interpreter
in that group can do — it limits what an *invocation of `fhs` from that
group* does. This is intentional: HoneySnatch does not attempt to
mediate general-purpose interpreter access.

### Sidecar processes and unrelated code paths

Nothing in the consent gate mediates external programs. An operator
running `hostapd`, `wpa_supplicant`, or `hcxdumptool` directly is
outside HoneySnatch's control surface entirely. Log those separately.

### Physical, RF-layer, and hardware-level attacks

Rogue devices in RF range, adapter firmware issues, driver bugs, and
side-channels via the radio hardware are not in scope.

## Deployment prerequisites for the trusted-process model

The trusted-process model is only valid when the deployment satisfies
these conditions:

1. **No third-party plugin loading.** This release does not define
   any plugin discovery mechanism. There are no `entry_points`
   in `pyproject.toml`, no `pluggy` hooks, no `importlib.import_module`
   of caller-supplied names, no dynamic loading of code from the
   consent-token store or the audit log. The regression test at
   `tests/test_no_dynamic_code_loading.py` asserts this and refuses
   to pass if a future commit introduces one without a corresponding
   threat-model amendment.
2. **Declared, reviewed dependency set — with the honest caveat that
   the graph is not yet hash-locked.** `pyproject.toml`,
   `requirements.txt`, and `requirements-linux.txt` declare a
   minimum-version dependency graph (`>=` constraints). Adding a
   runtime dependency requires a code review that considers this
   threat model. But an operator installing `honeysnatch` from PyPI
   or a fresh clone will resolve those `>=` constraints to whatever
   versions the index offers at install time — the graph is NOT
   currently hash-pinned. That means a supply-chain compromise of a
   listed dependency (or a semver-compatible malicious release of
   one) collapses the trusted-process assumption. Producing a
   platform/Python-specific lock file with `--require-hashes` and
   verifying it in CI is tracked as **HS-09** in `SECURITY.md` and
   is the correct long-term control for this prerequisite. Until
   HS-09 lands, deployments that need strong dependency provenance
   should pin transitively themselves (`pip-tools`, `uv lock`, or
   equivalent) against the reviewed minimum-version graph.
3. **No REPL / debugger attached in production.** Running `fhs` under
   `pdb`, `ptpython`, `pyrasite`, or any other in-process shell voids
   the model.
4. **Operator-controlled process boundary.** `fhs` is invoked as a
   dedicated process by the operator or by a systemd unit under their
   control. The process is not shared with other Python applications
   or with a long-running kernel/notebook.
5. **Standard user account hygiene.** The operator is trusted; the
   group with `fhs` access is the operators' group, not a broadly
   shared shell group.

If any of these are violated, TB-01 becomes exploitable in your
environment. See the mitigations below.

## Mitigations when the trusted-process model does not hold

If your deployment DOES include untrusted in-process code (a plugin
ecosystem, a shared multi-tenant Python service, or third-party code
you cannot audit), the consent gate is insufficient. The reviewer
identified the correct architectural response as Option B in the v0.1.5
follow-up: move authorization enforcement across a process boundary.

Concretely: run the radio-capable code paths as a separate privileged
broker process that accepts requests over a Unix socket, validates
each request's authentication independently (a cryptographic signature
or a Unix-peer credential check that binds to a known caller identity),
scopes each request to a specific BSSID with an explicit expiry, and
emits its own audit trail. The unprivileged HoneySnatch process
becomes an untrusted client of that broker — it cannot forge
authorization by mutating any Python state on its own side, because
the broker does not trust anything the client asserts.

This is a significant refactor and is tracked as a v0.2 roadmap item.
Until it lands, deployments that need resistance to hostile in-process
code should either:

- Wrap `fhs` in a separate OS user account with tighter file system
  and network policy, or
- Use MAC (SELinux / AppArmor) profiles that constrain what the
  `fhs` process can do at the kernel level, or
- Not use HoneySnatch in that environment.

## Change log

- **v0.1.10** — CI-config relaxation: dropped style-modernization
  ruff packs (UP, N) that generated ~1000 cosmetic Optional->|None
  suggestions, and added a numpy mypy override to work around numpy
  2.x stubs using PEP 695 syntax. No content change to the boundary,
  no application code changed.
- **v0.1.9** — Build-system fix (`build-backend` corrected to
  `setuptools.build_meta`). No content change to the boundary; CI
  fix only, restores `pip install -e ".[dev]"` reproducibility that
  the trusted-process model's dependency prerequisite depends on.
- **v0.1.8** — Version-neutral wording in deployment prerequisite #1
  (DOC-02, v0.1.7 review). Content unchanged.
- **v0.1.7** — Reframed prerequisite #2 to accurately describe the
  minimum-version dependency graph (TM-01, v0.1.6 review); no
  content change to the trusted-process boundary itself.
- **v0.1.6** — Initial document; declared in response to TB-01.
