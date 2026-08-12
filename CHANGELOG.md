# Changelog

All notable changes to honeysnatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-08-12

### Changed

- **DOC-02** — THREAT_MODEL.md deployment prerequisite #1 made
  version-neutral ("this release" instead of "HoneySnatch v0.1.6").
  No content change. Change log section at the bottom of the doc
  still names versions (as it should).

### Added

- `tests/test_threat_model_version_stability.py` (2 tests) —
  refuses to pass if the Deployment prerequisites section names any
  specific `vX.Y.Z`; also asserts the Change log DOES name the
  current `__version__` so a future bump that forgets to update the
  doc fails at test time.

### Test posture

- 372 pytest passing (was 370), 3 skipped, 0 failing.
- 191/191 smoke.

## [0.1.7] - 2026-08-12

### Changed

- **TM-01** — Reframed THREAT_MODEL.md's "fixed dependency set"
  prerequisite to accurately describe the declared minimum-version
  graph, with an explicit caveat that a compromised dep collapses
  the boundary. Hash-locking is cross-linked to HS-09 as the correct
  long-term control.
- **RE-02** — Release-zip exclusion pattern fixed: uses
  `'*/.git/*' -x '.git'` so `.git/` is excluded but `.github/`,
  `.gitignore`, and `.gitattributes` are preserved. My v0.1.6 zip's
  `'*.git*'` glob was too broad and stripped all of them.
- **DL-01** — `honeysnatch/isolation/wpaspy.py` refactored so the
  path arg to `importlib.util.spec_from_file_location` is inlined
  at each call site as a `Path(__file__)`-rooted expression rather
  than passed through an intermediate loop variable. The dynamic-
  loading regression test can now verify package-anchoring
  statically.

### Added

- `honeysnatch/security_docs.py` — runtime handle for the packaged
  SECURITY.md and THREAT_MODEL.md copies (`security_docs_dir()`,
  `read_security_policy()`, `read_threat_model()`,
  `iter_security_docs()`).
- `honeysnatch/data/security/` — byte-identical copies of the
  canonical repo-root SECURITY.md and THREAT_MODEL.md, shipped
  inside the wheel via `[tool.setuptools.package-data]`. Fixes
  **TM-02**: `pip install honeysnatch` operators now receive the
  controlling boundary statement.
- `tests/test_security_docs_in_wheel.py` (4 tests) — enforces
  byte-parity between packaged and root copies, verifies runtime
  helpers return expected headers.
- `tests/test_release_manifest.py` (14 tests) — parameterized check
  that required release-archive paths exist (`.github/workflows/
  ci.yml`, `.gitignore`, `.gitattributes`, and the load-bearing
  modules/docs), plus a CI-workflow content check for Python 3.10/
  3.11/3.12 matrix + pytest. Fixes **RE-02**.
- `tests/test_no_dynamic_code_loading.py` — detector extended to
  cover `spec_from_file_location`, `module_from_spec`, loader
  `.exec_module`, `runpy.run_path`/`run_module`, and bare `eval`/
  `exec`. New `test_wpaspy_loader_path_is_package_anchored` locks
  the wpaspy loader path to `Path(__file__)`. Fixes **DL-01**.
- README now links `THREAT_MODEL.md` alongside `SECURITY.md`.

### Test posture

- 370 pytest passing (was 351), 3 skipped, 0 failing.
- 191/191 smoke.

## [0.1.6] - 2026-08-12

### Changed

- **TB-01** — Trusted-process threat-model boundary declared. New
  `THREAT_MODEL.md` names what the consent gate does and does not
  defend against, following the v0.1.5 reviewer's Option A path.
  Consent-gate docstrings in `honeysnatch/isolation/consent.py`
  updated to stop claiming resistance to hostile in-process code
  — that was never actually true, and pretending otherwise was the
  root cause of TB-01. Option B (privileged broker refactor) is on
  the v0.2 roadmap.
- **DOC-01** — Removed duplicate `## v0.1.4 hardening summary`
  header in SECURITY.md. Also cleaned up the v0.1.3 duplicate the
  v0.1.5 fix missed.

### Added

- `tests/test_no_dynamic_code_loading.py` codifying the trusted-
  process prerequisites: no `entry_points` plugin discovery, no
  `pluggy`/`stevedore` in deps, no dynamic import of caller-supplied
  strings anywhere in `honeysnatch/`. Refuses to pass if a future
  commit expands the surface without also updating THREAT_MODEL.md.

### Test posture

- 351 pytest passing (was 347), 3 skipped, 0 failing.
- 191/191 smoke.

## [0.1.0] - 2025-03-17

### Added

- **HoneyBadger Core** - Passive WiFi discovery engine with 802.11 packet parsing, channel hopping, and monitor mode support
- **WarrenMap** - RF signal visualization with Folium heatmaps and KML/Google Earth export
- **HoneyView** - Post-hoc analysis with pattern detection, evil twin identification, and HTML report generation
- **SentryWeb** - Continuous monitoring with rogue AP detection, encryption downgrade alerts, and configurable policy engine
- **BadgerTrack** - Indoor positioning via GPS/IMU sensor fusion
- **BlueScout** - Passive Bluetooth/BLE scanning via Ubertooth
- **CellGuard** - Cellular base station detection (GSM/LTE/5G NR) with rogue tower / IMSI catcher detection via SDR
- **Encrypted storage** - AES-256-GCM file encryption and optional SQLCipher database encryption
- **Tamper-evident audit logging** - HMAC-SHA256 chained append-only audit trail
- **PyQt6 desktop GUI** with tabbed panels for all modules
- **Click CLI** (`fhs`) with subcommands for scanning, analysis, monitoring, export, and audit
- **Export formats** - CSV, JSON, KML with optional encryption
- **MCC/MNC operator database** for cellular carrier identification
- **OUI vendor database** for MAC address manufacturer lookup

### Hardware Support

- RTL-SDR (NooElec NESDR Nano 3) for GSM scanning via gr-gsm
- HackRF One (PortaPack H4M) for LTE/5G cell search via srsRAN
- Ubertooth One for Bluetooth scanning
- Any Linux-supported WiFi adapter with monitor mode
- GPS via gpsd
- Raspberry Pi CM5 deployment target
