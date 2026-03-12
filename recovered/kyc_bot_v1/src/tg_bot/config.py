"""
Configuration loader for the KYC bot.

Loads settings from config.json with optional .env overrides.

Real config keys from memory dump:
  DATABASE: {DATABASE_NAME, USERNAME, PASSWORD, HOST, PORT}
  TGBOT: {TOKEN, ADMIN_IDS, PRIVATE_KEY, CUSTOM_SUMSUB_DOMAIN, SHOW_REWARD_TITLES,
          INCLUDE_CASH_CARD_REWARDS, INCLUDE_POSITION_AIR_DROP_REWARDS}
  ACCOUNTS_MANAGE: {ACCOUNTS_FOR_KYC_GROUP_NAME, GROUP_TO_COLLECT_APPROVED_ACCOUNTS,
                    USERS_CAN_TAKE_ACCOUNTS, MAX_TAKE_ACCOUNTS_PER_USER,
                    MAX_TAKE_PER_REQUEST, DETECT_DUPLICATE_ACCOUNTS_BY_NAME, DOCS_INTERCEPT}
  CONNECTION: {REFRESH_PROXY_ON_ERROR}
  ISHUSHKA: {API_KEY, LICENSE_KEY, LICENSE_FILE}
  PARTNER: {PARTNER_SYSTEM_STATUS, PARTNER_ROYALTY_PERCENT}

Admin IDs from memory: [6544377406, 534354]
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


CONFIG_PATH = Path(__file__).parent.parent / "config.json"


@dataclass
class DatabaseConfig:
    """PostgreSQL connection settings."""
    DATABASE_NAME: str = "bybit"
    USERNAME: str = "postgres"
    PASSWORD: Optional[str] = None
    HOST: str = "localhost"
    PORT: int = 5432

    @property
    def dsn(self) -> str:
        """Return async SQLAlchemy DSN."""
        password_part = f":{self.PASSWORD}" if self.PASSWORD else ""
        return (
            f"postgresql+asyncpg://{self.USERNAME}{password_part}"
            f"@{self.HOST}:{self.PORT}/{self.DATABASE_NAME}"
        )

    @property
    def sync_dsn(self) -> str:
        """Return sync psycopg2 DSN (for Alembic)."""
        password_part = f":{self.PASSWORD}" if self.PASSWORD else ""
        return (
            f"postgresql+psycopg2://{self.USERNAME}{password_part}"
            f"@{self.HOST}:{self.PORT}/{self.DATABASE_NAME}"
        )


@dataclass
class TgBotConfig:
    """Telegram bot settings."""
    TOKEN: Optional[str] = None
    ADMIN_IDS: list[int] = field(default_factory=lambda: [6544377406, 534354])
    PRIVATE_KEY: Optional[str] = None  # RSA key for SumSub signing
    CUSTOM_SUMSUB_DOMAIN: Optional[str] = None
    SHOW_REWARD_TITLES: bool = True
    INCLUDE_CASH_CARD_REWARDS: bool = False
    INCLUDE_POSITION_AIR_DROP_REWARDS: bool = False


@dataclass
class AccountsManageConfig:
    """Account management settings."""
    ACCOUNTS_FOR_KYC_GROUP_NAME: str = "new"
    GROUP_TO_COLLECT_APPROVED_ACCOUNTS: str = "approved"
    USERS_CAN_TAKE_ACCOUNTS: bool = False
    MAX_TAKE_ACCOUNTS_PER_USER: int = 4
    MAX_TAKE_PER_REQUEST: int = 2
    DETECT_DUPLICATE_ACCOUNTS_BY_NAME: bool = False
    DOCS_INTERCEPT: bool = False  # Intercept document uploads for KYC


@dataclass
class ConnectionConfig:
    """Network/proxy connection settings."""
    REFRESH_PROXY_ON_ERROR: bool = True


@dataclass
class IshushkaConfig:
    """License server + AI chat settings (ishushka.com)."""
    API_KEY: Optional[str] = None
    LICENSE_KEY: Optional[str] = None
    LICENSE_FILE: Optional[str] = None
    ENABLED: bool = False
    MODEL: str = "gpt-5.1-chat"
    PROMPT: Optional[str] = None


@dataclass
class PartnerConfig:
    """Partner/referral system settings."""
    PARTNER_SYSTEM_STATUS: bool = False
    PARTNER_ROYALTY_PERCENT: float = 10.0


@dataclass
class Config:
    """Root configuration object."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    tgbot: TgBotConfig = field(default_factory=TgBotConfig)
    accounts_manage: AccountsManageConfig = field(default_factory=AccountsManageConfig)
    connection: ConnectionConfig = field(default_factory=ConnectionConfig)
    ishushka: IshushkaConfig = field(default_factory=IshushkaConfig)
    partner: PartnerConfig = field(default_factory=PartnerConfig)


def _apply_env_overrides(config: Config) -> None:
    """Override config values from environment variables."""
    if token := os.getenv("TGBOT_TOKEN"):
        config.tgbot.TOKEN = token
    if db_pass := os.getenv("DB_PASSWORD"):
        config.database.PASSWORD = db_pass
    if db_host := os.getenv("DB_HOST"):
        config.database.HOST = db_host
    if db_name := os.getenv("DB_NAME"):
        config.database.DATABASE_NAME = db_name
    if sumsub_key := os.getenv("SUMSUB_PRIVATE_KEY"):
        config.tgbot.PRIVATE_KEY = sumsub_key
    if sumsub_domain := os.getenv("CUSTOM_SUMSUB_DOMAIN"):
        config.tgbot.CUSTOM_SUMSUB_DOMAIN = sumsub_domain
    if ishushka_key := os.getenv("ISHUSHKA_API_KEY"):
        config.ishushka.API_KEY = ishushka_key
    if license_key := os.getenv("LICENSE_KEY"):
        config.ishushka.LICENSE_KEY = license_key
    if license_file := os.getenv("LICENSE_FILE"):
        config.ishushka.LICENSE_FILE = license_file
    if admin_ids := os.getenv("ADMIN_IDS"):
        try:
            config.tgbot.ADMIN_IDS = [int(x.strip()) for x in admin_ids.split(",")]
        except ValueError:
            pass


def _dict_to_dataclass(cls, data: dict):
    """Convert a dict to a dataclass, ignoring unknown keys."""
    import dataclasses
    field_names = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.items() if k in field_names}
    return cls(**filtered)


def load_config(path: Path | str | None = None) -> Config:
    """
    Load configuration from config.json and apply env overrides.

    Args:
        path: Optional path to config.json. Defaults to ../config.json relative to this file.

    Returns:
        Fully loaded Config object.
    """
    config_path = Path(path) if path else CONFIG_PATH

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = {}

    config = Config(
        database=_dict_to_dataclass(DatabaseConfig, raw.get("DATABASE", {})),
        tgbot=_dict_to_dataclass(TgBotConfig, raw.get("TGBOT", {})),
        accounts_manage=_dict_to_dataclass(AccountsManageConfig, raw.get("ACCOUNTS_MANAGE", {})),
        connection=_dict_to_dataclass(ConnectionConfig, raw.get("CONNECTION", {})),
        ishushka=_dict_to_dataclass(IshushkaConfig, raw.get("ISHUSHKA", {})),
        partner=_dict_to_dataclass(PartnerConfig, raw.get("PARTNER", {})),
    )

    _apply_env_overrides(config)
    return config


# Singleton config instance
config = load_config()
