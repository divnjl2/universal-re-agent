"""
Bybit Manager configuration — loads from config.json.

Config structure recovered from server config files:
- Database: PostgreSQL connection
- Captcha services: capmonster, 2captcha, etc.
- Proxy providers: dataimpulse, iproyal, nodemaven
- Email providers: Gmail, Mail.ru, Outlook (OAuth2), Rambler, firstmail, iCloud
- License: ishushka.com license server
- Telegram bot: token, admin IDs
- API: host, port, allowed origins
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("bybit_manager.config")

# Captcha defaults recovered from traffic
CAPMONSTER_API_URL = "https://api.capmonster.cloud"
CAPMONSTER_USER_AGENT = "python-anycaptcha"
CAPMONSTER_KEY_LENGTH = 32

RECAPTCHA_SITE_KEY = "6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6"
CAPTCHA_SCENE_LOGIN = "31000"

# Proxy provider defaults recovered from traffic
PROXY_PROVIDERS = {
    "iproyal": {
        "host": "geo.iproyal.com",
        "port": 11250,
        "credential_pattern": "{user}_country-{cc}_session-{session}_lifetime-168h:{pass}",
    },
    "dataimpulse": {
        "host": "gw.dataimpulse.com",
        "port": 823,
        "credential_pattern": "{user}_country-{cc}_session-{session}_lifetime-168h:{pass}",
    },
    "nodemaven": {
        "host": "gate.nodemaven.com",
        "port": 8080,
        "credential_pattern": "{user}_country-{cc}_session-{session}_lifetime-168h:{pass}",
    },
}

# AdsPower local API
ADSPOWER_API_URL = "http://localhost:50325"

# License server
LICENSE_SERVER_URL = "https://ishushka.com"


class Config:
    """Application configuration loaded from config.json."""

    DEFAULT_CONFIG_PATH = "config/config.json"

    def __init__(self, config_path: Optional[str] = None):
        self._data: Dict[str, Any] = {}
        config_path = config_path or self.DEFAULT_CONFIG_PATH
        if os.path.exists(config_path):
            self.load(config_path)
        else:
            logger.warning("Config file not found: %s, using defaults", config_path)

    def load(self, path: str) -> None:
        """Load config from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            self._data = json.load(f)
        logger.info("Config loaded from %s", path)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by dot-separated key path."""
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    # ================================================================
    # Database
    # ================================================================

    @property
    def database_url(self) -> str:
        db = self._data.get("database", {})
        user = db.get("username", "postgres")
        password = db.get("password", "Bybit_Secure_789456")
        host = db.get("host", "localhost")
        port = db.get("port", 5432)
        name = db.get("database_name", "bybit")
        return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{name}"

    # ================================================================
    # API
    # ================================================================

    @property
    def api_host(self) -> str:
        return self.get("api.host", "0.0.0.0")

    @property
    def api_port(self) -> int:
        return self.get("api.port", 8000)

    @property
    def api_allow_origins(self) -> List[str]:
        return self.get("api.allow_origins", ["*"])

    # ================================================================
    # Captcha
    # ================================================================

    @property
    def captcha_services(self) -> List[Dict[str, Any]]:
        """Get captcha service configurations."""
        services = self._data.get("captcha_services", {})
        result = []
        for name, config in services.items():
            if config.get("api_key"):
                result.append({
                    "service": name,
                    "api_key": config["api_key"],
                    "enabled": config.get("enabled", True),
                    "priority": config.get("priority", 0),
                })
        return sorted(result, key=lambda x: x.get("priority", 0))

    # ================================================================
    # Proxy
    # ================================================================

    @property
    def proxy_services(self) -> Dict[str, Dict[str, Any]]:
        return self._data.get("proxy_services", {})

    # ================================================================
    # Email
    # ================================================================

    @property
    def email_services(self) -> Dict[str, Dict[str, Any]]:
        return self._data.get("email_services", {})

    # ================================================================
    # License
    # ================================================================

    @property
    def license_key(self) -> str:
        return self.get("license.key", "")

    @property
    def license_server(self) -> str:
        return self.get("license.server", "https://ishushka.com")

    # ================================================================
    # Telegram
    # ================================================================

    @property
    def telegram_token(self) -> str:
        return self.get("telegram.token", "")

    @property
    def telegram_admin_ids(self) -> List[int]:
        return self.get("telegram.admin_ids", [])

    # ================================================================
    # SumSub
    # ================================================================

    @property
    def sumsub_private_key(self) -> str:
        return self.get("sumsub.private_key", "")

    @property
    def sumsub_app_token(self) -> str:
        return self.get("sumsub.app_token", "")

    # ================================================================
    # Bybit defaults
    # ================================================================

    @property
    def default_ref_code(self) -> str:
        return self.get("bybit.default_ref_code", "")

    @property
    def default_country_code(self) -> str:
        return self.get("bybit.default_country_code", "")
