"""
Path configuration — file system paths used by the application.
"""

from __future__ import annotations

import os
from pathlib import Path


# Base project directory (where the app is installed)
BASE_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Config
CONFIG_DIR = BASE_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Data
DATA_DIR = BASE_DIR / "data"
ACCOUNTS_DIR = DATA_DIR / "accounts"
EXPORT_DIR = DATA_DIR / "export"

# Logs
LOGS_DIR = BASE_DIR / "logs"

# Temp
TEMP_DIR = BASE_DIR / "temp"


def ensure_dirs() -> None:
    """Create all required directories."""
    for d in [CONFIG_DIR, DATA_DIR, ACCOUNTS_DIR, EXPORT_DIR, LOGS_DIR, TEMP_DIR]:
        d.mkdir(parents=True, exist_ok=True)
