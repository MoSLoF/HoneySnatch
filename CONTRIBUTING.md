# Contributing to FlyingHoneySnitch

Thank you for your interest in contributing! This document provides guidelines for
contributing to the project.

## Development Setup

```bash
# Clone the repository (correct org: MoSLoF)
git clone https://github.com/MoSLoF/FlyingHoneySnitch.git
cd FlyingHoneySnitch

# Pull vendor submodules (libwifi)
git submodule init
git submodule update

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\Activate.ps1    # Windows (PowerShell)

# Install in editable/development mode with all extras
pip install -e ".[dev,all]"

# Validate the install (no hardware required)
python smoke_test.py
```

## Running Tests

```bash
# Full pytest suite
python -m pytest tests/ -v

# With coverage report
python -m pytest tests/ --cov=flyinghoneysnitch --cov-report=term-missing

# Smoke test — fast, no root, no hardware
python smoke_test.py

# Specific test modules
python -m pytest tests/cellular/test_detector.py -v
python -m pytest tests/isolation/ -v
python -m pytest tests/core/ -v
```

## Code Quality

We use `ruff` for linting and `mypy` for type checking:

```bash
# Lint
ruff check flyinghoneysnitch/

# Auto-fix lint issues
ruff check flyinghoneysnitch/ --fix

# Format
ruff format flyinghoneysnitch/

# Type check
mypy flyinghoneysnitch/
```

All PRs must pass `ruff check` with zero errors and `python smoke_test.py` with zero failures.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure all tests pass: `python -m pytest tests/ -v`
4. Ensure smoke test passes: `python smoke_test.py`
5. Ensure linting is clean: `ruff check flyinghoneysnitch/`
6. Update documentation if adding new features or CLI commands
7. Submit a PR with a clear description of changes

## Code Style

- Python 3.10+ with type hints on all public APIs
- Line length: 100 characters (enforced by ruff)
- Docstrings on all public classes, methods, and functions
- Follow existing patterns in the codebase (thread-based scanners, dataclass models)
- New scanner modules should follow the `BluetoothScanner` / `CellularScanner` pattern:
  - `start()` / `stop()` lifecycle
  - `on_device_found` / `on_device_updated` callbacks
  - Thread-safe internal registry with `_lock`

## Module Architecture

| Module | Purpose |
|--------|---------|
| `core/` | WiFi packet capture, parsing, scanning engine |
| `analysis/` | Post-hoc analytics, pattern detection, HTML reports |
| `bluetooth/` | BlueScout — BLE/BT scanning, AD parser, device classifier |
| `cellular/` | CellGuard — GSM/LTE/5G scanning, rogue tower detection |
| `db/` | SQLAlchemy ORM, database manager, migrations |
| `gui/` | PyQt6 desktop application |
| `isolation/` | AirSnitch — client isolation attacks, hostap integration, libwifi |
| `mapping/` | GIS utilities, signal heatmaps, KML/Folium export |
| `monitoring/` | SentryWeb — continuous alerting, policy engine |
| `positioning/` | GPS client, IMU reader, sensor fusion |
| `utils/` | Config, logging, AES-256-GCM crypto, HMAC audit log |
| `cli/` | Click CLI subcommands (`fhs`) |

## Adding a New Module

1. Create the module directory under `flyinghoneysnitch/`
2. Add a `__init__.py` with `__all__` exports
3. Add the module to `flyinghoneysnitch/__init__.py` imports if appropriate
4. Add DB schema tables to `db/schema.py` and persistence methods to `db/database.py`
5. Add a CLI subcommand group in `cli/` and register it in `cli/main.py`
6. Add smoke test sections to `smoke_test.py`
7. Add test files under `tests/`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
- For questions about the project, open a Discussion

## Links

- **Repository:** https://github.com/MoSLoF/FlyingHoneySnitch
- **Homepage:** https://ihbv.io
