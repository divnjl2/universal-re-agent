"""
Shared fixtures for kyc_bot_v1 recovered code tests.

Adds the src/ directory to sys.path so tg_bot can be imported,
and provides common test fixtures.
"""
import sys
from pathlib import Path

import pytest

# Add src/ to path so `import tg_bot` works without installing
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture
def tmp_config_json(tmp_path):
    """Create a temporary config.json with test data."""
    import json

    config_data = {
        "DATABASE": {
            "DATABASE_NAME": "test_db",
            "USERNAME": "test_user",
            "PASSWORD": "secret123",
            "HOST": "10.0.0.1",
            "PORT": 5433,
        },
        "TGBOT": {
            "TOKEN": "123456:ABC-DEF",
            "ADMIN_IDS": [111, 222],
            "PRIVATE_KEY": "sumsub-secret-key",
        },
        "ACCOUNTS_MANAGE": {
            "ACCOUNTS_FOR_KYC_GROUP_NAME": "kyc_new",
            "MAX_TAKE_ACCOUNTS_PER_USER": 8,
        },
        "ISHUSHKA": {
            "API_KEY": "ish-key-abc",
            "ENABLED": True,
            "MODEL": "gpt-4-turbo",
            "PROMPT": "You are a helpful KYC assistant.",
        },
        "PARTNER": {
            "PARTNER_SYSTEM_STATUS": True,
            "PARTNER_ROYALTY_PERCENT": 15.0,
        },
    }

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    return config_file


@pytest.fixture
def empty_config_path(tmp_path):
    """Return a path to a non-existent config.json."""
    return tmp_path / "nonexistent_config.json"


@pytest.fixture
def license_data_valid():
    """Sample valid license data dict (as would be in license.json)."""
    from datetime import datetime, timedelta

    future = datetime.utcnow() + timedelta(days=30)
    return {
        "key": "test-license-key-abc123",
        "hwid": "",  # empty means any hwid
        "cancel_date": future.isoformat(),
        "modules": ["kyc_bot", "reverify"],
    }


@pytest.fixture
def license_data_expired():
    """Sample expired license data dict."""
    return {
        "key": "expired-key",
        "hwid": "",
        "cancel_date": "2020-01-01T00:00:00",
        "modules": ["*"],
    }


@pytest.fixture
def license_data_wildcard():
    """License that allows all modules."""
    from datetime import datetime, timedelta

    future = datetime.utcnow() + timedelta(days=365)
    return {
        "key": "wildcard-key",
        "hwid": "",
        "cancel_date": future.isoformat(),
        "modules": ["*"],
    }
