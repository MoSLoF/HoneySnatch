# Contributing to FlyingHoneySnitch

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/iHBV/FlyingHoneySnitch.git
cd FlyingHoneySnitch

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in development mode with all extras
pip install -e ".[dev,all]"
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=flyinghoneysnitch --cov-report=term-missing

# Run a specific test file
python -m pytest tests/cellular/test_detector.py -v
```

## Code Quality

We use `ruff` for linting and `mypy` for type checking:

```bash
# Lint
ruff check flyinghoneysnitch/

# Type check
mypy flyinghoneysnitch/

# Auto-format
ruff format flyinghoneysnitch/
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure all tests pass and linting is clean
4. Update documentation if adding new features
5. Submit a PR with a clear description of changes

## Code Style

- Python 3.10+ with type hints on all public APIs
- Line length: 100 characters
- Docstrings on all public classes, methods, and functions
- Follow existing patterns in the codebase (e.g., thread-based scanners, dataclass models)

## Module Architecture

| Module | Purpose |
|--------|---------|
| `core/` | WiFi packet capture, parsing, scanning engine |
| `analysis/` | Post-hoc analytics, pattern detection, reporting |
| `bluetooth/` | Bluetooth/BLE scanning via Ubertooth |
| `cellular/` | Cellular tower detection via SDR (CellGuard) |
| `db/` | SQLAlchemy database persistence |
| `gui/` | PyQt6 desktop application |
| `mapping/` | GIS utilities, signal heatmaps, KML export |
| `monitoring/` | Continuous monitoring, alerting, policy engine |
| `positioning/` | Indoor positioning via GPS/IMU fusion |
| `utils/` | Configuration, logging, crypto, audit |
| `cli/` | Click CLI commands |

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
