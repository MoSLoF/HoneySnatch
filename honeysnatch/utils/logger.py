"""Logging setup for honeysnatch."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from honeysnatch import __app_name__

_logger: Optional[logging.Logger] = None


def get_logger(name: str = __app_name__) -> logging.Logger:
    """Get a logger instance for the given module name."""
    return logging.getLogger(f"{__app_name__}.{name}")


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure the root logger for honeysnatch.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to a log file.

    Returns:
        The configured root logger.
    """
    global _logger

    root = logging.getLogger(__app_name__)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers
    root.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    # File handler
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(path))
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    _logger = root
    return root
