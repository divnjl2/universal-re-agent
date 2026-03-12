"""
Unit tests for recovered KYC bot code.

Tests verify STRUCTURE and LOGIC of recovered modules without
requiring a running bot, database, or network access.
"""
import inspect
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure src/ is on path (conftest.py handles this, but be explicit)
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# ===================================================================
# 1. CONFIG TESTS
# ===================================================================


class TestConfigLoadNoFile:
    """load_config() works when config.json does not exist."""

    def test_load_config_missing_file_returns_defaults(self, empty_config_path):
        from tg_bot.config import load_config

        cfg = load_config(path=empty_config_path)
        assert cfg.database.DATABASE_NAME == "bybit"
        assert cfg.database.USERNAME == "postgres"
        assert cfg.database.HOST == "localhost"
        assert cfg.database.PORT == 5432
        assert cfg.tgbot.TOKEN is None
        assert cfg.ishushka.ENABLED is False
        assert cfg.partner.PARTNER_SYSTEM_STATUS is False

    def test_load_config_missing_file_admin_ids_default(self, empty_config_path):
        from tg_bot.config import load_config

        cfg = load_config(path=empty_config_path)
        assert cfg.tgbot.ADMIN_IDS == [6544377406, 534354]


class TestConfigLoadFromJson:
    """load_config() reads config.json correctly."""

    def test_database_section(self, tmp_config_json):
        from tg_bot.config import load_config

        cfg = load_config(path=tmp_config_json)
        assert cfg.database.DATABASE_NAME == "test_db"
        assert cfg.database.USERNAME == "test_user"
        assert cfg.database.PASSWORD == "secret123"
        assert cfg.database.HOST == "10.0.0.1"
        assert cfg.database.PORT == 5433

    def test_tgbot_section(self, tmp_config_json):
        from tg_bot.config import load_config

        cfg = load_config(path=tmp_config_json)
        assert cfg.tgbot.TOKEN == "123456:ABC-DEF"
        assert cfg.tgbot.ADMIN_IDS == [111, 222]
        assert cfg.tgbot.PRIVATE_KEY == "sumsub-secret-key"

    def test_ishushka_section(self, tmp_config_json):
        from tg_bot.config import load_config

        cfg = load_config(path=tmp_config_json)
        assert cfg.ishushka.ENABLED is True
        assert cfg.ishushka.MODEL == "gpt-4-turbo"
        assert cfg.ishushka.PROMPT == "You are a helpful KYC assistant."
        assert cfg.ishushka.API_KEY == "ish-key-abc"

    def test_partner_section(self, tmp_config_json):
        from tg_bot.config import load_config

        cfg = load_config(path=tmp_config_json)
        assert cfg.partner.PARTNER_SYSTEM_STATUS is True
        assert cfg.partner.PARTNER_ROYALTY_PERCENT == 15.0

    def test_accounts_manage_section(self, tmp_config_json):
        from tg_bot.config import load_config

        cfg = load_config(path=tmp_config_json)
        assert cfg.accounts_manage.ACCOUNTS_FOR_KYC_GROUP_NAME == "kyc_new"
        assert cfg.accounts_manage.MAX_TAKE_ACCOUNTS_PER_USER == 8


class TestIshushkaConfigFields:
    """IshushkaConfig has ENABLED, MODEL, PROMPT fields."""

    def test_ishushka_has_expected_fields(self):
        from tg_bot.config import IshushkaConfig

        cfg = IshushkaConfig()
        assert hasattr(cfg, "ENABLED")
        assert hasattr(cfg, "MODEL")
        assert hasattr(cfg, "PROMPT")
        assert hasattr(cfg, "API_KEY")
        assert hasattr(cfg, "LICENSE_KEY")
        assert hasattr(cfg, "LICENSE_FILE")

    def test_ishushka_defaults(self):
        from tg_bot.config import IshushkaConfig

        cfg = IshushkaConfig()
        assert cfg.ENABLED is False
        assert cfg.MODEL == "gpt-5.1-chat"
        assert cfg.PROMPT is None


class TestConfigEnvOverrides:
    """Environment variable overrides work."""

    def test_env_overrides_token(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"TGBOT_TOKEN": "env-token-999"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.tgbot.TOKEN == "env-token-999"

    def test_env_overrides_db_password(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"DB_PASSWORD": "env-pass"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.database.PASSWORD == "env-pass"

    def test_env_overrides_db_host(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"DB_HOST": "192.168.1.100"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.database.HOST == "192.168.1.100"

    def test_env_overrides_admin_ids(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"ADMIN_IDS": "100,200,300"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.tgbot.ADMIN_IDS == [100, 200, 300]

    def test_env_overrides_ishushka_key(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"ISHUSHKA_API_KEY": "env-ish-key"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.ishushka.API_KEY == "env-ish-key"

    def test_env_overrides_license_key(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"LICENSE_KEY": "env-lic-key"}):
            cfg = load_config(path=empty_config_path)
        assert cfg.ishushka.LICENSE_KEY == "env-lic-key"

    def test_env_override_trumps_json(self, tmp_config_json):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"TGBOT_TOKEN": "env-override-token"}):
            cfg = load_config(path=tmp_config_json)
        # env should override json value "123456:ABC-DEF"
        assert cfg.tgbot.TOKEN == "env-override-token"

    def test_invalid_admin_ids_env_ignored(self, empty_config_path):
        from tg_bot.config import load_config

        with patch.dict(os.environ, {"ADMIN_IDS": "not,valid,numbers"}):
            cfg = load_config(path=empty_config_path)
        # Should keep default since parsing fails
        assert cfg.tgbot.ADMIN_IDS == [6544377406, 534354]


class TestDatabaseDSN:
    """DSN property format is correct."""

    def test_dsn_with_password(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig(
            DATABASE_NAME="mydb", USERNAME="admin",
            PASSWORD="pass123", HOST="db.host", PORT=5432,
        )
        assert db.dsn == "postgresql+asyncpg://admin:pass123@db.host:5432/mydb"

    def test_dsn_without_password(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig(
            DATABASE_NAME="mydb", USERNAME="admin",
            PASSWORD=None, HOST="localhost", PORT=5432,
        )
        assert db.dsn == "postgresql+asyncpg://admin@localhost:5432/mydb"

    def test_sync_dsn_with_password(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig(
            DATABASE_NAME="mydb", USERNAME="admin",
            PASSWORD="pass123", HOST="db.host", PORT=5432,
        )
        assert db.sync_dsn == "postgresql+psycopg2://admin:pass123@db.host:5432/mydb"

    def test_sync_dsn_without_password(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig(
            DATABASE_NAME="mydb", USERNAME="admin",
            PASSWORD=None, HOST="localhost", PORT=5432,
        )
        assert db.sync_dsn == "postgresql+psycopg2://admin@localhost:5432/mydb"

    def test_dsn_uses_asyncpg_driver(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig()
        assert "asyncpg" in db.dsn

    def test_sync_dsn_uses_psycopg2_driver(self):
        from tg_bot.config import DatabaseConfig

        db = DatabaseConfig()
        assert "psycopg2" in db.sync_dsn


# ===================================================================
# 2. MODEL TESTS
# ===================================================================


class TestModelImports:
    """All models can be imported from tg_bot.models."""

    def test_import_base(self):
        from tg_bot.models import Base
        assert Base is not None

    def test_import_user(self):
        from tg_bot.models import User
        assert User is not None

    def test_import_bybit_account(self):
        from tg_bot.models import BybitAccount
        assert BybitAccount is not None

    def test_import_price_country(self):
        from tg_bot.models import PriceCountry
        assert PriceCountry is not None

    def test_import_reverify_payment(self):
        from tg_bot.models import ReverifyPayment
        assert ReverifyPayment is not None

    def test_import_payment(self):
        from tg_bot.models import Payment
        assert Payment is not None

    def test_import_bot_settings(self):
        from tg_bot.models import BotSettings
        assert BotSettings is not None


class TestModelTableNames:
    """Models have expected table names."""

    def test_user_tablename(self):
        from tg_bot.models import User
        assert User.__tablename__ == "users"

    def test_bybit_account_tablename(self):
        from tg_bot.models import BybitAccount
        assert BybitAccount.__tablename__ == "bybit_account"

    def test_payment_tablename(self):
        from tg_bot.models import Payment
        assert Payment.__tablename__ == "payments"

    def test_price_country_tablename(self):
        from tg_bot.models import PriceCountry
        assert PriceCountry.__tablename__ == "price_countries"

    def test_reverify_payment_tablename(self):
        from tg_bot.models import ReverifyPayment
        assert ReverifyPayment.__tablename__ == "reverify_payments"

    def test_bot_settings_tablename(self):
        from tg_bot.models import BotSettings
        assert BotSettings.__tablename__ == "bot_settings"


class TestBybitAccountFields:
    """BybitAccount has expected key fields."""

    def test_has_cookies_field(self):
        from tg_bot.models import BybitAccount
        mapper = inspect.getmembers(BybitAccount)
        field_names = [name for name, _ in mapper]
        assert "cookies" in field_names

    def test_has_proxy_field(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "proxy")

    def test_has_kyc_status_field(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "kyc_status")

    def test_has_kyc_level_field(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "kyc_level")

    def test_has_last_provider_field(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "last_provider")

    def test_has_facial_verification_required(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "facial_verification_required")

    def test_has_database_id_pk(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "database_id")

    def test_has_uid(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "uid")

    def test_has_group_name(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "group_name")

    def test_has_email_address(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "email_address")

    def test_has_country(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "country")

    def test_has_first_name_last_name(self):
        from tg_bot.models import BybitAccount
        assert hasattr(BybitAccount, "first_name")
        assert hasattr(BybitAccount, "last_name")


class TestUserModelFields:
    """User model has expected fields."""

    def test_has_id(self):
        from tg_bot.models import User
        assert hasattr(User, "id")

    def test_has_full_name(self):
        from tg_bot.models import User
        assert hasattr(User, "full_name")

    def test_has_username(self):
        from tg_bot.models import User
        assert hasattr(User, "username")

    def test_has_balance(self):
        from tg_bot.models import User
        assert hasattr(User, "balance")

    def test_has_wallet_address(self):
        from tg_bot.models import User
        assert hasattr(User, "wallet_address")

    def test_has_can_take_accounts(self):
        from tg_bot.models import User
        assert hasattr(User, "can_take_accounts")

    def test_has_invited_by(self):
        from tg_bot.models import User
        assert hasattr(User, "invited_by")


class TestPriceCountryLogic:
    """PriceCountry display_limit and is_available logic.

    Uses unittest.mock to patch SA-instrumented attributes on the instance,
    since __new__ + __dict__ is not enough for SA's descriptor protocol.
    """

    def test_display_limit_unlimited(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=0), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=5):
            assert pc.display_limit == "5/\u221e"

    def test_display_limit_with_limit(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=10), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=3):
            assert pc.display_limit == "3/10"

    def test_is_available_active_unlimited(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "active", new_callable=PropertyMock, return_value=True), \
             patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=0), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=100):
            assert pc.is_available is True

    def test_is_available_active_within_limit(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "active", new_callable=PropertyMock, return_value=True), \
             patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=10), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=5):
            assert pc.is_available is True

    def test_is_available_active_at_limit(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "active", new_callable=PropertyMock, return_value=True), \
             patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=10), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=10):
            assert pc.is_available is False

    def test_is_available_inactive(self):
        from tg_bot.models.country_price import PriceCountry
        from unittest.mock import PropertyMock

        pc = PriceCountry.__new__(PriceCountry)
        with patch.object(type(pc), "active", new_callable=PropertyMock, return_value=False), \
             patch.object(type(pc), "day_limit", new_callable=PropertyMock, return_value=0), \
             patch.object(type(pc), "used_day_limit", new_callable=PropertyMock, return_value=0):
            assert pc.is_available is False


# ===================================================================
# 3. DTO TESTS
# ===================================================================


class TestServiceResult:
    """ServiceResult.ok() and .fail() work correctly."""

    def test_ok_is_successful(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.ok(data={"id": 42})
        assert r.success is True
        assert r.data == {"id": 42}
        assert r.error is None

    def test_ok_without_data(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.ok()
        assert r.success is True
        assert r.data is None

    def test_fail_is_not_successful(self):
        from tg_bot.dto.service_result import ServiceResult, ServiceError

        err = ServiceError(code="NOT_FOUND", message="Account not found")
        r = ServiceResult.fail(error=err)
        assert r.success is False
        assert r.data is None
        assert r.error is not None
        assert r.error.code == "NOT_FOUND"
        assert r.error.message == "Account not found"

    def test_fail_with_message_shortcut(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.fail(message="something broke")
        assert r.success is False
        assert r.error is not None
        assert r.error.message == "something broke"
        assert r.error.code == "UNKNOWN"

    def test_fail_default_error(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.fail()
        assert r.success is False
        assert r.error is not None

    def test_repr_ok(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.ok(data="hello")
        assert "ok" in repr(r)
        assert "hello" in repr(r)

    def test_repr_fail(self):
        from tg_bot.dto.service_result import ServiceResult

        r = ServiceResult.fail(message="bad")
        assert "fail" in repr(r)


class TestServiceError:
    """ServiceError has code and message."""

    def test_default_code(self):
        from tg_bot.dto.service_result import ServiceError

        err = ServiceError()
        assert err.code == "UNKNOWN"
        assert err.message == ""

    def test_custom_code_message(self):
        from tg_bot.dto.service_result import ServiceError

        err = ServiceError(code="TIMEOUT", message="Request timed out")
        assert err.code == "TIMEOUT"
        assert err.message == "Request timed out"


class TestUserDTO:
    """UserDTO properties work correctly."""

    def test_is_admin_with_matching_id(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=100, admin_ids=[100, 200])
        assert u.is_admin is True

    def test_is_admin_without_matching_id(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=999, admin_ids=[100, 200])
        assert u.is_admin is False

    def test_is_admin_no_admin_ids(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=100)
        assert u.is_admin is False

    def test_mention_with_full_name(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=123, full_name="John Doe")
        assert u.mention == '<a href="tg://user?id=123">John Doe</a>'

    def test_mention_with_username_fallback(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=123, username="johndoe")
        assert u.mention == '<a href="tg://user?id=123">johndoe</a>'

    def test_mention_with_id_fallback(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=123)
        assert u.mention == '<a href="tg://user?id=123">123</a>'

    def test_url_with_username(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=123, username="johndoe")
        assert u.url == "https://t.me/johndoe"

    def test_url_without_username(self):
        from tg_bot.dto.user import UserDTO

        u = UserDTO(id=123)
        assert u.url == "tg://user?id=123"


class TestReverifyDTOs:
    """Reverify DTOs have expected fields."""

    def test_reverify_account_info_fields(self):
        from tg_bot.dto.reverify import ReverifyAccountInfo

        info = ReverifyAccountInfo(
            database_id=504, uid=12345, name="test_acc",
            country="US", kyc_status="SUCCESS",
            kyc_level=1, last_provider="PROVIDER_SUMSUB",
            facial_verification_required=False,
        )
        assert info.database_id == 504
        assert info.uid == 12345
        assert info.kyc_status == "SUCCESS"

    def test_reverify_result_success(self):
        from tg_bot.dto.reverify import ReverifyResult

        r = ReverifyResult(
            success=True, account_id=504,
            message="OK", verification_url="https://example.com/verify",
        )
        assert r.success is True
        assert r.verification_url == "https://example.com/verify"

    def test_reverify_result_failure(self):
        from tg_bot.dto.reverify import ReverifyResult

        r = ReverifyResult(
            success=False, account_id=504,
            error="Provider unavailable",
        )
        assert r.success is False
        assert r.error == "Provider unavailable"


# ===================================================================
# 4. LICENSE TESTS
# ===================================================================


class TestTokenPayload:
    """TokenPayload dataclass structure."""

    def test_default_values(self):
        from tg_bot.license import TokenPayload

        tp = TokenPayload()
        assert tp.hwid == ""
        assert tp.cancel_date is None
        assert tp.modules == []
        assert tp.max_devices == 1
        assert tp.exp is None

    def test_custom_values(self):
        from tg_bot.license import TokenPayload

        tp = TokenPayload(
            hwid="abc123", cancel_date="2026-12-31",
            modules=["kyc_bot", "reverify"], max_devices=3, exp=9999999999,
        )
        assert tp.hwid == "abc123"
        assert tp.modules == ["kyc_bot", "reverify"]
        assert tp.max_devices == 3


class TestLicenseInfo:
    """LicenseInfo allows() logic and cancel_date_str property."""

    def test_allows_when_invalid(self):
        from tg_bot.license import LicenseInfo

        li = LicenseInfo(valid=False, modules=["*"])
        assert li.allows("kyc_bot") is False

    def test_allows_wildcard(self):
        from tg_bot.license import LicenseInfo

        li = LicenseInfo(valid=True, modules=["*"])
        assert li.allows("anything") is True
        assert li.allows("kyc_bot") is True

    def test_allows_specific_module(self):
        from tg_bot.license import LicenseInfo

        li = LicenseInfo(valid=True, modules=["kyc_bot", "reverify"])
        assert li.allows("kyc_bot") is True
        assert li.allows("reverify") is True
        assert li.allows("admin_panel") is False

    def test_allows_empty_modules(self):
        from tg_bot.license import LicenseInfo

        li = LicenseInfo(valid=True, modules=[])
        assert li.allows("kyc_bot") is False

    def test_cancel_date_str_with_date(self):
        from tg_bot.license import LicenseInfo

        dt = datetime(2026, 6, 15, 14, 30)
        li = LicenseInfo(valid=True, cancel_date=dt)
        assert li.cancel_date_str == "15.06.2026 14:30"

    def test_cancel_date_str_no_date(self):
        from tg_bot.license import LicenseInfo

        li = LicenseInfo(valid=True, cancel_date=None)
        assert li.cancel_date_str == "\u0431\u0435\u0441\u0441\u0440\u043e\u0447\u043d\u0430\u044f"  # "бессрочная"


class TestLicenseClientStructure:
    """LicenseClient instantiation and method existence."""

    def test_client_instantiation(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        assert client._server_urls == ["https://api.ishushka.com"]
        assert client._token is None
        assert client._hwid is None

    def test_client_custom_server_urls(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient(server_urls=["https://custom.server.com"])
        assert client._server_urls == ["https://custom.server.com"]

    def test_from_license_file_nonexistent(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient.from_license_file("nonexistent_file.json")
        assert client._license_data == {}

    def test_from_license_file_existing(self, tmp_path):
        import json
        from tg_bot.license import LicenseClient

        lic_file = tmp_path / "license.json"
        data = {"key": "test-key", "modules": ["*"]}
        lic_file.write_text(json.dumps(data), encoding="utf-8")

        client = LicenseClient.from_license_file(lic_file)
        assert client._license_data["key"] == "test-key"

    def test_collect_hwid_returns_string(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        hwid = client._collect_hwid()
        assert isinstance(hwid, str)
        assert len(hwid) == 32  # sha256 hex truncated to 32

    def test_collect_hwid_is_deterministic(self):
        from tg_bot.license import LicenseClient

        c1 = LicenseClient()
        c2 = LicenseClient()
        assert c1._collect_hwid() == c2._collect_hwid()

    def test_get_server_url(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        assert client._get_server_url() == "https://api.ishushka.com"

    def test_build_payload_structure(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        client._license_data = {"key": "abc"}
        payload = client._build_payload()
        assert "hwid" in payload
        assert "key" in payload
        assert payload["key"] == "abc"
        assert payload["product"] == "kyc_bot"
        assert payload["version"] == "1.0"

    def test_sign_produces_hex(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        client._license_data = {"key": "secret-key"}
        sig = client._sign("challenge-data")
        assert isinstance(sig, str)
        # HMAC-SHA256 hex is 64 chars
        assert len(sig) == 64

    def test_is_token_valid_no_token(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        assert client._is_token_valid() is False

    def test_is_token_valid_expired(self):
        import time
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        client._token = "some-token"
        client._token_expires = time.time() - 100  # expired
        assert client._is_token_valid() is False

    def test_is_token_valid_fresh(self):
        import time
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        client._token = "some-token"
        client._token_expires = time.time() + 3600  # 1 hour ahead
        assert client._is_token_valid() is True


class TestLicenseDecodeAndVerify:
    """_decode_and_verify parses license data correctly."""

    def test_valid_license(self, license_data_valid):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        info = client._decode_and_verify(license_data_valid)
        assert info.valid is True
        assert info.modules == ["kyc_bot", "reverify"]
        assert info.cancel_date is not None
        assert info.error is None

    def test_expired_license(self, license_data_expired):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        info = client._decode_and_verify(license_data_expired)
        assert info.valid is False
        assert info.error == "License expired"

    def test_wildcard_license(self, license_data_wildcard):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        info = client._decode_and_verify(license_data_wildcard)
        assert info.valid is True
        assert info.allows("anything") is True

    def test_hwid_mismatch(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        data = {
            "hwid": "definitely-wrong-hwid-that-wont-match",
            "cancel_date": (datetime.utcnow() + timedelta(days=30)).isoformat(),
            "modules": ["*"],
        }
        info = client._decode_and_verify(data)
        assert info.valid is False
        assert "HWID mismatch" in info.error

    def test_no_cancel_date_means_perpetual(self):
        from tg_bot.license import LicenseClient

        client = LicenseClient()
        data = {"hwid": "", "modules": ["*"]}
        info = client._decode_and_verify(data)
        assert info.valid is True
        assert info.cancel_date is None

    def test_cancele_date_typo_handled(self):
        """The code handles the 'cancele_date' typo from real data."""
        from tg_bot.license import LicenseClient

        future = (datetime.utcnow() + timedelta(days=30)).isoformat()
        client = LicenseClient()
        data = {"hwid": "", "cancele_date": future, "modules": ["*"]}
        info = client._decode_and_verify(data)
        assert info.valid is True
        assert info.cancel_date is not None


class TestLicenseClientMethods:
    """LicenseClient has all expected async methods."""

    def test_has_get_license_method(self):
        from tg_bot.license import LicenseClient
        assert hasattr(LicenseClient, "get_license")
        assert inspect.iscoroutinefunction(LicenseClient.get_license)

    def test_has_require_license_method(self):
        from tg_bot.license import LicenseClient
        assert hasattr(LicenseClient, "require_license")
        assert inspect.iscoroutinefunction(LicenseClient.require_license)

    def test_has_close_method(self):
        from tg_bot.license import LicenseClient
        assert hasattr(LicenseClient, "close")
        assert inspect.iscoroutinefunction(LicenseClient.close)

    def test_has_fetch_challenge(self):
        from tg_bot.license import LicenseClient
        assert hasattr(LicenseClient, "_fetch_challenge")

    def test_has_refresh_token(self):
        from tg_bot.license import LicenseClient
        assert hasattr(LicenseClient, "_refresh_token")


# ===================================================================
# 5. SERVICE STRUCTURE TESTS
# ===================================================================


class TestSumSubServiceStructure:
    """SumSubService can be instantiated and has expected methods."""

    def test_instantiation(self):
        from tg_bot.services.sumsub import SumSubService

        svc = SumSubService()
        assert svc.base_url == "https://direct-api.sumsub.com"
        assert svc.proxy is None

    def test_instantiation_with_proxy(self):
        from tg_bot.services.sumsub import SumSubService

        svc = SumSubService(proxy="http://proxy:8080")
        assert svc.proxy == "http://proxy:8080"

    def test_sign_request_produces_hmac(self):
        from tg_bot.services.sumsub import SumSubService

        svc = SumSubService()
        svc.secret_key = "test-secret"
        sig = svc._sign_request("GET", "/resources/applicants", 1234567890)
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA256 hex

    def test_auth_headers_structure(self):
        from tg_bot.services.sumsub import SumSubService

        svc = SumSubService()
        svc.secret_key = "test-secret"
        headers = svc._auth_headers("GET", "/test")
        assert "X-App-Token" in headers
        assert "X-App-Access-Ts" in headers
        assert "X-App-Access-Sig" in headers
        assert "Content-Type" in headers

    def test_has_create_applicant(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.create_applicant)

    def test_has_get_applicant_status(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.get_applicant_status)

    def test_has_get_applicant_actions(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.get_applicant_actions)

    def test_has_get_inspections(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.get_inspections)

    def test_has_check_ip(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.check_ip)

    def test_has_is_logged_in(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.is_logged_in)

    def test_has_get_websdk_link(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.get_websdk_link)

    def test_has_websdk_init(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.websdk_init)

    def test_has_reset_applicant(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.reset_applicant)

    def test_has_create_bypass(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.create_bypass)

    def test_has_create_onfido_bypass(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.create_onfido_bypass)

    def test_has_check_seller(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.check_seller)

    def test_has_report_seller(self):
        from tg_bot.services.sumsub import SumSubService
        assert inspect.iscoroutinefunction(SumSubService.report_seller)


class TestBybitKycServiceStructure:
    """BybitKycService can be instantiated and has expected methods."""

    def test_instantiation_default(self):
        from tg_bot.services.bybit import BybitKycService

        svc = BybitKycService()
        assert svc.cookies == {}
        assert svc.proxy is None

    def test_instantiation_with_cookies(self):
        from tg_bot.services.bybit import BybitKycService

        cookies = {"session_id": "abc123"}
        svc = BybitKycService(cookies=cookies, proxy="http://proxy:3128")
        assert svc.cookies == cookies
        assert svc.proxy == "http://proxy:3128"

    def test_headers_include_user_agent(self):
        from tg_bot.services.bybit import BybitKycService

        svc = BybitKycService()
        assert "User-Agent" in svc._headers
        assert "Mozilla" in svc._headers["User-Agent"]

    def test_headers_include_referer(self):
        from tg_bot.services.bybit import BybitKycService

        svc = BybitKycService()
        assert "Referer" in svc._headers
        assert "bybitglobal.com" in svc._headers["Referer"]

    def test_has_get_kyc_provider(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_kyc_provider)

    def test_has_get_kyc_info(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_kyc_info)

    def test_has_get_verification_sdk_info(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_verification_sdk_info)

    def test_has_get_personal_info(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_personal_info)

    def test_has_need_confirm_pi(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.need_confirm_pi)

    def test_has_submit_questionnaire(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.submit_questionnaire)

    def test_has_kyc_provider_callback(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.kyc_provider_callback)

    def test_has_get_face_token(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_face_token)

    def test_has_check_face_auth_status(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.check_face_auth_status)

    def test_has_risk_verify(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.risk_verify)

    def test_has_get_awards(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.get_awards)

    def test_has_search_awards(self):
        from tg_bot.services.bybit import BybitKycService
        assert inspect.iscoroutinefunction(BybitKycService.search_awards)


class TestGetKycLinkDataclass:
    """GetKycLink dataclass structure."""

    def test_defaults(self):
        from tg_bot.services.bybit import GetKycLink

        link = GetKycLink()
        assert link.id is None
        assert link.url is None

    def test_with_values(self):
        from tg_bot.services.bybit import GetKycLink

        link = GetKycLink(id="app-123", url="https://sumsub.com/verify/abc")
        assert link.id == "app-123"
        assert link.url == "https://sumsub.com/verify/abc"


class TestIshushkaServiceStructure:
    """IshushkaService instantiation and method existence."""

    def test_instantiation(self):
        from tg_bot.services.ishushka import IshushkaService

        svc = IshushkaService()
        assert hasattr(svc, "enabled")
        assert hasattr(svc, "api_key")
        assert hasattr(svc, "model")
        assert hasattr(svc, "system_prompt")

    def test_has_ask_method(self):
        from tg_bot.services.ishushka import IshushkaService
        assert inspect.iscoroutinefunction(IshushkaService.ask)


class TestStatisticsServiceStructure:
    """Statistics service functions exist."""

    def test_get_verification_stats_exists(self):
        from tg_bot.services.statistics import get_verification_stats
        assert inspect.iscoroutinefunction(get_verification_stats)

    def test_format_stats_text_exists(self):
        from tg_bot.services.statistics import format_stats_text
        assert callable(format_stats_text)

    def test_export_payments_csv_exists(self):
        from tg_bot.services.statistics import export_payments_csv
        assert inspect.iscoroutinefunction(export_payments_csv)

    def test_export_reverify_csv_exists(self):
        from tg_bot.services.statistics import export_reverify_csv
        assert inspect.iscoroutinefunction(export_reverify_csv)

    def test_format_stats_text_output(self):
        from tg_bot.services.statistics import format_stats_text

        stats = {
            "total": 100,
            "today_count": 5,
            "today_amount": 45.00,
            "week_count": 30,
            "week_amount": 270.50,
            "daily": [
                {"date": "2026-03-12", "count": 5, "amount": 45.00},
                {"date": "2026-03-11", "count": 8, "amount": 72.00},
            ],
            "by_country": [
                {"iso2_code": "US", "country_full_name": "United States", "count": 20, "amount": 180.0},
            ],
            "reverify_total": 15,
        }
        text = format_stats_text(stats)
        assert "100" in text
        assert "$45.00" in text
        assert "United States" in text
        assert "15" in text


# ===================================================================
# 6. KEYBOARD TESTS
# ===================================================================


class TestMainReplyKeyboard:
    """main_reply_keyboard returns ReplyKeyboardMarkup."""

    def test_returns_reply_keyboard_markup(self):
        from tg_bot.keyboards.base import main_reply_keyboard
        from aiogram.types import ReplyKeyboardMarkup

        kb = main_reply_keyboard()
        assert isinstance(kb, ReplyKeyboardMarkup)

    def test_has_two_buttons(self):
        from tg_bot.keyboards.base import main_reply_keyboard

        kb = main_reply_keyboard()
        # First row has 2 buttons
        assert len(kb.keyboard) == 1
        assert len(kb.keyboard[0]) == 2

    def test_button_texts(self):
        from tg_bot.keyboards.base import main_reply_keyboard

        kb = main_reply_keyboard()
        texts = [btn.text for btn in kb.keyboard[0]]
        assert "KYC ACCOUNTS" in texts
        assert "REVERIFY ACCOUNTS" in texts

    def test_resize_keyboard(self):
        from tg_bot.keyboards.base import main_reply_keyboard

        kb = main_reply_keyboard()
        assert kb.resize_keyboard is True

    def test_is_persistent(self):
        from tg_bot.keyboards.base import main_reply_keyboard

        kb = main_reply_keyboard()
        assert kb.is_persistent is True


class TestAdminMenuKeyboard:
    """admin_menu_keyboard returns InlineKeyboardMarkup."""

    def test_returns_inline_keyboard_markup(self):
        from tg_bot.keyboards.other import admin_menu_keyboard
        from aiogram.types import InlineKeyboardMarkup

        kb = admin_menu_keyboard()
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_has_expected_callbacks(self):
        from tg_bot.keyboards.other import admin_menu_keyboard

        kb = admin_menu_keyboard()
        all_callbacks = []
        for row in kb.inline_keyboard:
            for btn in row:
                if btn.callback_data:
                    all_callbacks.append(btn.callback_data)

        assert "admin_users_list" in all_callbacks
        assert "admin_stats" in all_callbacks
        assert "admin_mailing" in all_callbacks
        assert "admin_toggle_bot" in all_callbacks
        assert "admin_change_prices" in all_callbacks
        assert "admin_reset_limits" in all_callbacks


class TestFaceVerificationKeyboard:
    """build_face_verification_keyboard returns InlineKeyboardMarkup."""

    def test_without_ticket(self):
        from tg_bot.keyboards.reverify import build_face_verification_keyboard
        from aiogram.types import InlineKeyboardMarkup

        kb = build_face_verification_keyboard(db_id=504)
        assert isinstance(kb, InlineKeyboardMarkup)
        assert len(kb.inline_keyboard) == 1  # only generate link button

    def test_with_ticket(self):
        from tg_bot.keyboards.reverify import build_face_verification_keyboard
        from aiogram.types import InlineKeyboardMarkup

        kb = build_face_verification_keyboard(db_id=504, ticket="tkt-123")
        assert isinstance(kb, InlineKeyboardMarkup)
        assert len(kb.inline_keyboard) == 2  # generate link + check status


class TestCallbackDataClasses:
    """CallbackData subclasses pack/unpack correctly."""

    def test_acc_page_cb_pack(self):
        from tg_bot.keyboards.reverify import AccPageCb

        cb = AccPageCb(page=3)
        packed = cb.pack()
        assert "3" in packed
        assert packed.startswith("acc_page:")

    def test_acc_select_cb_pack(self):
        from tg_bot.keyboards.reverify import AccSelectCb

        cb = AccSelectCb(db_id=504)
        packed = cb.pack()
        assert "504" in packed
        assert packed.startswith("acc_select:")

    def test_reward_select_cb_pack(self):
        from tg_bot.keyboards.reverify import RewardSelectCb

        cb = RewardSelectCb(db_id=504, award_id="award_001")
        packed = cb.pack()
        assert "504" in packed
        assert "award_001" in packed

    def test_generate_face_link_cb_pack(self):
        from tg_bot.keyboards.reverify import GenerateFaceLinkCb

        cb = GenerateFaceLinkCb(db_id=504)
        packed = cb.pack()
        assert "504" in packed

    def test_check_face_status_cb_pack(self):
        from tg_bot.keyboards.reverify import CheckFaceStatusCb

        cb = CheckFaceStatusCb(db_id=504, ticket="tkt-abc")
        packed = cb.pack()
        assert "504" in packed
        assert "tkt-abc" in packed


class TestUserManagementKeyboard:
    """user_management_keyboard returns correct structure."""

    def test_returns_inline_keyboard(self):
        from tg_bot.keyboards.other import user_management_keyboard
        from aiogram.types import InlineKeyboardMarkup

        kb = user_management_keyboard(user_id=12345)
        assert isinstance(kb, InlineKeyboardMarkup)

    def test_contains_user_id_in_callbacks(self):
        from tg_bot.keyboards.other import user_management_keyboard

        kb = user_management_keyboard(user_id=12345)
        all_callbacks = []
        for row in kb.inline_keyboard:
            for btn in row:
                if btn.callback_data:
                    all_callbacks.append(btn.callback_data)

        # Should have callbacks referencing the user_id
        assert any("12345" in cb for cb in all_callbacks)

    def test_pin_text_unpinned(self):
        from tg_bot.keyboards.other import user_management_keyboard

        kb = user_management_keyboard(user_id=1, pinned=False)
        all_texts = [btn.text for row in kb.inline_keyboard for btn in row]
        pin_texts = [t for t in all_texts if "Закрепить" in t]
        assert len(pin_texts) == 1

    def test_pin_text_pinned(self):
        from tg_bot.keyboards.other import user_management_keyboard

        kb = user_management_keyboard(user_id=1, pinned=True)
        all_texts = [btn.text for row in kb.inline_keyboard for btn in row]
        pin_texts = [t for t in all_texts if "Открепить" in t]
        assert len(pin_texts) == 1


class TestProviderSelectKeyboard:
    """provider_select_keyboard has provider options."""

    def test_has_three_providers(self):
        from tg_bot.keyboards.other import provider_select_keyboard

        kb = provider_select_keyboard(user_id=999)
        all_callbacks = [
            btn.callback_data
            for row in kb.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        provider_cbs = [cb for cb in all_callbacks if "provider_select" in cb]
        assert len(provider_cbs) == 3
        assert any("PROVIDER_SUMSUB" in cb for cb in provider_cbs)
        assert any("PROVIDER_ONFIDO" in cb for cb in provider_cbs)
        assert any("PROVIDER_AAI" in cb for cb in provider_cbs)


class TestConfirmDeleteKeyboard:
    """confirm_delete_user_keyboard returns confirm/cancel buttons."""

    def test_has_confirm_and_cancel(self):
        from tg_bot.keyboards.other import confirm_delete_user_keyboard

        kb = confirm_delete_user_keyboard(user_id=555)
        all_callbacks = [
            btn.callback_data
            for row in kb.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert f"confirm_delete_555" in all_callbacks
        assert f"cancel_delete_555" in all_callbacks
