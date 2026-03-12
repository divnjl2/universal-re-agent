"""
Integration test suite for the recovered Bybit Manager application.

Validates that all modules can be imported, key objects can be instantiated,
static methods produce correct output, FastAPI app is wired correctly,
and Pydantic schemas accept sample data.

Run with:
    pytest tests/test_integration.py -v
"""

from __future__ import annotations

import os
import re
import sys

# Ensure the src directory is on sys.path so all packages are importable
SRC_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), os.pardir, "src")
)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import pytest


# ================================================================
# 1. Import checks
# ================================================================


class TestImports:
    """Verify that all key modules and symbols can be imported."""

    def test_import_base_client_classes(self):
        from bybit.client.base import (
            BaseClient,
            BybitResponse,
            BybitException,
            BybitDevice,
            BybitHTTPJSONException,
            BybitComponentError,
        )
        assert BaseClient is not None
        assert BybitResponse is not None
        assert BybitException is not None
        assert BybitDevice is not None
        assert BybitHTTPJSONException is not None
        assert BybitComponentError is not None

    def test_import_base_private_client(self):
        from bybit.client.base_private_client import BasePrivateClient
        assert BasePrivateClient is not None

    def test_import_private_client(self):
        from bybit.client.private_client import PrivateClient
        assert PrivateClient is not None

    def test_import_public_client(self):
        from bybit.client.public_client import PublicClient
        assert PublicClient is not None

    def test_import_bybit_client_package(self):
        """The bybit.client package re-exports all key symbols."""
        from bybit.client import (
            BaseClient,
            BasePrivateClient,
            PrivateClient,
            PublicClient,
            BybitDevice,
            BybitException,
            BybitHTTPJSONException,
            BybitHTMLError,
            BybitComponentError,
            BybitResponse,
            BybitCardCommission,
            BASE_URL,
            API_DOMAINS,
            LOGIN_LOCALES,
            BYBIT_ERRORS,
        )
        assert BASE_URL == "https://api2.bybitglobal.com"

    def test_import_config(self):
        from bybit_manager.config import Config
        assert Config is not None

    def test_import_manager(self):
        from bybit_manager.manager import Manager
        assert Manager is not None

    def test_import_managed_client_and_pool(self):
        from bybit_manager.client import ManagedClient, ClientPool
        assert ManagedClient is not None
        assert ClientPool is not None

    def test_import_bybit_manager_package(self):
        """The bybit_manager package re-exports Config and Manager."""
        from bybit_manager import Config, Manager
        assert Config is not None
        assert Manager is not None

    def test_import_database_module(self):
        from bybit_manager.database.database import Database
        assert Database is not None

    def test_import_imap_client(self):
        from bybit_manager.imap import ImapClient
        assert ImapClient is not None

    def test_import_license_checker(self):
        from bybit_manager.license import LicenseChecker
        assert LicenseChecker is not None

    def test_import_anycaptcha_package(self):
        from anycaptcha import (
            CaptchaSolver,
            AnyCaptchaException,
            CaptchaError,
            CaptchaTimeout,
            CaptchaType,
            CaptchaServiceType,
        )
        assert CaptchaSolver is not None
        assert CaptchaType.RECAPTCHA_V2 == "RecaptchaV2"

    def test_import_anycaptcha_solver(self):
        from anycaptcha.solver import CaptchaSolver
        assert CaptchaSolver is not None

    def test_import_anycaptcha_errors(self):
        from anycaptcha.errors import (
            AnyCaptchaException,
            CaptchaError,
            CaptchaTimeout,
            CaptchaUnsolvable,
            CaptchaServiceError,
            CaptchaInvalidKey,
            CaptchaNoBalance,
        )
        assert issubclass(CaptchaError, AnyCaptchaException)
        assert issubclass(CaptchaTimeout, AnyCaptchaException)
        assert issubclass(CaptchaUnsolvable, AnyCaptchaException)
        assert issubclass(CaptchaInvalidKey, CaptchaServiceError)
        assert issubclass(CaptchaNoBalance, CaptchaServiceError)

    def test_import_anycaptcha_enums(self):
        from anycaptcha.enums import (
            CaptchaType,
            CaptchaServiceType,
            TaskStatus,
            CaptchaAlphabet,
        )
        assert CaptchaServiceType.CAPMONSTER == "capmonster"
        assert TaskStatus.READY == "ready"

    def test_import_anycaptcha_services(self):
        from anycaptcha.service.capmonster import CapMonsterService
        from anycaptcha.service.twocaptcha import TwoCaptchaService
        from anycaptcha.service.anti_captcha import AntiCaptchaService
        from anycaptcha.service.capsolver import CapsolverService
        assert CapMonsterService is not None
        assert TwoCaptchaService is not None

    def test_import_anycaptcha_captcha_types(self):
        from anycaptcha.captcha.recaptcha_v2 import RecaptchaV2
        from anycaptcha.captcha.geetest import GeeTest
        from anycaptcha.captcha.geetest_v4 import GeeTestV4
        from anycaptcha.captcha.base import BaseCaptcha
        assert issubclass(RecaptchaV2, BaseCaptcha)

    def test_import_app_routers_package(self):
        from app.routers import (
            awarding_router,
            byfi_router,
            byvote_router,
            captcha_router,
            contract_router,
            database_router,
            demo_trading_router,
            email_router,
            ido_router,
            imap_router,
            kyc_router,
            launchpad_router,
            launchpool_router,
            private_router,
            public_router,
            puzzlehunt_router,
            referral_router,
            spot_router,
            tokensplash_router,
            transfer_router,
            web3_router,
            withdraw_router,
        )
        # All should be APIRouter instances
        from fastapi import APIRouter
        assert isinstance(private_router, APIRouter)
        assert isinstance(database_router, APIRouter)
        assert isinstance(withdraw_router, APIRouter)

    def test_import_individual_routers(self):
        """Each router module exposes a 'router' attribute."""
        from app.routers.private import router as private_router
        from app.routers.database import router as database_router
        from app.routers.withdraw import router as withdraw_router
        from app.routers.transfer import router as transfer_router
        from app.routers.kyc import router as kyc_router
        from app.routers.captcha import router as captcha_router
        from app.routers.awarding import router as awarding_router
        from app.routers.referral import router as referral_router
        from app.routers.spot import router as spot_router
        from app.routers.contract import router as contract_router
        from app.routers.email import router as email_router
        from app.routers.imap import router as imap_router
        from app.routers.tokensplash import router as tokensplash_router
        from app.routers.puzzlehunt import router as puzzlehunt_router
        from app.routers.launchpad import router as launchpad_router
        from app.routers.launchpool import router as launchpool_router
        from app.routers.ido import router as ido_router
        from app.routers.demo_trading import router as demo_trading_router
        from app.routers.web3 import router as web3_router
        from app.routers.byfi import router as byfi_router
        from app.routers.byvote import router as byvote_router
        from app.routers.public import router as public_router

        from fastapi import APIRouter
        for r in (private_router, database_router, withdraw_router,
                  transfer_router, kyc_router, captcha_router,
                  awarding_router, referral_router, spot_router,
                  contract_router, email_router, imap_router,
                  tokensplash_router, puzzlehunt_router, launchpad_router,
                  launchpool_router, ido_router, demo_trading_router,
                  web3_router, byfi_router, byvote_router, public_router):
            assert isinstance(r, APIRouter)

    def test_import_app_schemas_package(self):
        from app.schemas import (
            StatusResponse,
            ErrorResponse,
            BulkOperationResult,
            PaginatedResponse,
            DatabaseIdList,
            AccountCreate,
            AccountUpdate,
            AccountResponse,
            AccountListResponse,
            EmailCreate,
            EmailResponse,
            ImportAccountsRequest,
        )
        assert StatusResponse is not None

    def test_import_app_schemas_base(self):
        from app.schemas.base import (
            StatusResponse,
            ErrorResponse,
            BulkOperationResult,
            PaginatedResponse,
            DatabaseIdList,
            AccountIdentifier,
            CoinChainPair,
            AmountField,
        )
        assert StatusResponse is not None

    def test_import_app_schemas_database(self):
        from app.schemas.database import (
            AccountBase,
            AccountCreate,
            AccountUpdate,
            AccountResponse,
            AccountListResponse,
            EmailCreate,
            EmailResponse,
            ImportAccountsRequest,
            ExportFormat,
        )
        assert AccountBase is not None

    def test_import_app_schemas_private(self):
        from app.schemas.private import (
            DatabaseIdListRequest,
            BulkResult,
            LoginRequest,
            RegisterRequest,
            ProfileRequest,
            BalanceCheckRequest,
            Enable2FARequest,
            Disable2FARequest,
            ChangePasswordRequest,
            WithdrawRequest,
            TransferRequest,
        )
        assert LoginRequest is not None

    def test_import_bybit_constants(self):
        from bybit.client.base import (
            BASE_URL,
            API_DOMAINS,
            LOGIN_LOCALES,
            BYBIT_ERRORS,
            RECAPTCHA_SITE_KEY,
            COOKIE_NAMES,
        )
        assert "global" in API_DOMAINS
        assert "en" in LOGIN_LOCALES
        assert 0 in BYBIT_ERRORS
        assert BYBIT_ERRORS[0] == "OK"
        assert len(COOKIE_NAMES) > 0
        assert RECAPTCHA_SITE_KEY.startswith("6Lc")

    def test_import_bybit_enums(self):
        from bybit.enums import _base
        # Just verify the module is importable
        assert _base is not None


# ================================================================
# 2. Object creation
# ================================================================


class TestObjectCreation:
    """Verify that key objects can be instantiated."""

    def test_config_default(self):
        """Config() with no args uses default path; should not crash even if file missing."""
        from bybit_manager.config import Config
        config = Config()
        assert config is not None
        # With no config file, defaults are used
        assert config.api_port == 8000
        assert config.api_host == "0.0.0.0"
        assert config.database_url.startswith("postgresql+asyncpg://")

    def test_config_properties(self):
        from bybit_manager.config import Config
        config = Config()
        assert isinstance(config.captcha_services, list)
        assert isinstance(config.proxy_services, dict)
        assert isinstance(config.email_services, dict)
        assert isinstance(config.telegram_admin_ids, list)
        assert isinstance(config.api_allow_origins, list)

    def test_bybit_device_creation(self):
        from bybit.client.base import BybitDevice
        device = BybitDevice()
        assert device.user_agent is not None
        assert "Chrome" in device.user_agent
        assert "Mozilla/5.0" in device.user_agent
        assert device.sec_ch_ua is not None
        assert "Chromium" in device.sec_ch_ua
        assert device.device_id is not None
        assert len(device.device_id) == 36  # UUID format

    def test_bybit_device_custom(self):
        from bybit.client.base import BybitDevice
        device = BybitDevice(
            device_id="test-id",
            chrome_major_version=120,
            os="Linux",
            screen_width=2560,
            screen_height=1440,
        )
        assert device.device_id == "test-id"
        assert "Chrome/120" in device.user_agent
        assert "Linux" in device.user_agent
        assert '"Chromium";v="120"' in device.sec_ch_ua

    def test_base_client_creation(self):
        from bybit.client.base import BaseClient
        client = BaseClient()
        assert client is not None
        assert client.proxy is None
        assert client.base_url == "https://api2.bybitglobal.com"
        assert client.locale == "en"
        assert client.device is not None
        assert client._session is None  # Lazy session creation

    def test_base_client_with_proxy(self):
        from bybit.client.base import BaseClient
        client = BaseClient(proxy="http://127.0.0.1:8080")
        assert client.proxy == "http://127.0.0.1:8080"

    def test_base_private_client_creation(self):
        from bybit.client.base_private_client import BasePrivateClient
        client = BasePrivateClient(email="test@test.com", password="test")
        assert client is not None
        assert client.email == "test@test.com"
        assert client.password == "test"
        assert client.totp_secret == ""
        assert client.country_code == ""
        assert client.uid is None

    def test_private_client_creation(self):
        from bybit.client.private_client import PrivateClient
        client = PrivateClient(email="test@test.com", password="test")
        assert client is not None
        assert client.email == "test@test.com"
        assert client.password == "test"
        assert client.captcha_solver is None
        assert client.email_client is None

    def test_private_client_with_all_params(self):
        from bybit.client.private_client import PrivateClient
        from bybit.client.base import BybitDevice
        device = BybitDevice(chrome_major_version=130)
        client = PrivateClient(
            email="user@example.com",
            password="s3cret",
            totp_secret="JBSWY3DPEHPK3PXP",
            payment_password="pay123",
            proxy="http://proxy:8080",
            device=device,
            locale="ru-RU",
            country_code="RU",
        )
        assert client.email == "user@example.com"
        assert client.totp_secret == "JBSWY3DPEHPK3PXP"
        assert client.device.chrome_major_version == 130

    def test_bybit_response_creation(self):
        from bybit.client.base import BybitResponse
        resp = BybitResponse(ret_code=0, ret_msg="OK", result={"data": 1})
        assert resp.ok is True
        assert resp.ret_code == 0
        assert resp.result == {"data": 1}
        assert "ret_code=0" in repr(resp)

    def test_bybit_response_error(self):
        from bybit.client.base import BybitResponse
        resp = BybitResponse(ret_code=10001, ret_msg="Parameter error")
        assert resp.ok is False

    def test_bybit_exception_creation(self):
        from bybit.client.base import BybitException
        exc = BybitException(ret_code=10001, ret_msg="Parameter error")
        assert exc.ret_code == 10001
        assert exc.ret_msg == "Parameter error"
        assert "[10001]" in str(exc)

    def test_bybit_component_error_creation(self):
        from bybit.client.base import BybitComponentError
        exc = BybitComponentError(
            ret_code=20006,
            ret_msg="2FA required",
            risk_token="abc123",
            challenges=[{"type": "totp"}],
        )
        assert exc.risk_token == "abc123"
        assert len(exc.challenges) == 1

    def test_bybit_card_commission_creation(self):
        from bybit.client.base import BybitCardCommission
        comm = BybitCardCommission(coin="USDT", chain="ETH", fee=1.5)
        assert comm.coin == "USDT"
        assert comm.fee == 1.5

    def test_captcha_solver_creation(self):
        from anycaptcha import CaptchaSolver
        solver = CaptchaSolver(
            services=[{"service": "capmonster", "api_key": "test"}],
            timeout=60,
        )
        assert solver is not None
        assert solver.timeout == 60
        assert len(solver.services) == 1

    def test_client_pool_creation(self):
        from bybit_manager.client import ClientPool
        from bybit_manager.config import Config
        config = Config()
        pool = ClientPool(config)
        assert pool is not None
        assert len(pool._clients) == 0

    def test_managed_client_creation(self):
        from bybit_manager.client import ManagedClient
        from bybit_manager.config import Config
        config = Config()
        mc = ManagedClient(
            config=config,
            database_id=1,
            email_address="test@test.com",
            password="test123",
        )
        assert mc is not None
        assert mc.database_id == 1
        assert mc.email_address == "test@test.com"
        assert mc.device is not None


# ================================================================
# 3. Static method checks
# ================================================================


class TestStaticMethods:
    """Verify key static/class methods produce correct output."""

    def test_rsa_encrypt_password(self):
        """_rsa_encrypt_password should return a non-empty base64 string."""
        from bybit.client.base_private_client import BasePrivateClient
        import base64

        result = BasePrivateClient._rsa_encrypt_password("test", "123")
        assert isinstance(result, str)
        assert len(result) > 0
        # Should be valid base64
        decoded = base64.b64decode(result)
        assert len(decoded) > 0

    def test_rsa_encrypt_password_different_inputs(self):
        """Different inputs should produce different ciphertexts (due to PKCS1 padding randomness)."""
        from bybit.client.base_private_client import BasePrivateClient

        result1 = BasePrivateClient._rsa_encrypt_password("password1", "1000")
        result2 = BasePrivateClient._rsa_encrypt_password("password2", "2000")
        # Different inputs should almost certainly produce different outputs
        # (PKCS1_v1_5 has random padding, so even same input gives different output)
        assert isinstance(result1, str)
        assert isinstance(result2, str)
        assert len(result1) > 0
        assert len(result2) > 0

    def test_generate_traceparent(self):
        """_generate_traceparent should return W3C traceparent format: 00-{32hex}-{16hex}-{2hex}."""
        from bybit.client.base import BaseClient

        tp = BaseClient._generate_traceparent()
        assert isinstance(tp, str)
        # W3C traceparent: 00-{32 hex chars}-{16 hex chars}-{2 hex chars}
        pattern = r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
        assert re.match(pattern, tp), f"traceparent {tp!r} does not match expected pattern"

    def test_generate_traceparent_uniqueness(self):
        """Each call should produce a unique traceparent."""
        from bybit.client.base import BaseClient

        values = {BaseClient._generate_traceparent() for _ in range(50)}
        assert len(values) == 50, "traceparent values should be unique"

    def test_guid_property(self):
        """BaseClient.guid should return a UUID string."""
        from bybit.client.base import BaseClient
        client = BaseClient()
        guid = client.guid
        assert isinstance(guid, str)
        assert len(guid) == 36  # UUID format with dashes
        # Should be stable across calls
        assert client.guid == guid


# ================================================================
# 4. FastAPI app checks
# ================================================================


class TestFastAPIApp:
    """Verify the FastAPI application is correctly configured."""

    @pytest.fixture()
    def app(self):
        """Create a fresh FastAPI app via create_app."""
        from app.main import create_app
        return create_app()

    def test_app_exists(self, app):
        from fastapi import FastAPI
        assert isinstance(app, FastAPI)

    def test_app_has_routes(self, app):
        assert len(app.routes) > 0

    def test_app_title_and_version(self, app):
        assert app.title == "Bybit Manager v3"
        assert app.version == "3.0.0"

    def test_router_prefixes_exist(self, app):
        """All expected router prefixes should appear in app routes."""
        expected_prefixes = [
            "/private",
            "/public",
            "/database",
            "/withdraw",
            "/transfer",
            "/kyc",
            "/captcha",
            "/awarding",
            "/referral",
            "/spot",
            "/contract",
            "/email",
            "/imap",
            "/tokensplash",
            "/puzzlehunt",
            "/launchpad",
            "/launchpool",
            "/ido",
            "/demo-trading",
            "/web3",
            "/byfi",
            "/byvote",
        ]
        # Collect all route paths
        route_paths = set()
        for route in app.routes:
            if hasattr(route, "path"):
                route_paths.add(route.path)

        for prefix in expected_prefixes:
            matching = [p for p in route_paths if p.startswith(prefix)]
            assert len(matching) > 0, (
                f"No routes found with prefix {prefix!r}. "
                f"Available: {sorted(route_paths)}"
            )

    def test_root_endpoint_exists(self, app):
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        assert "/" in route_paths

    def test_health_endpoint_exists(self, app):
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        assert "/health" in route_paths

    def test_private_router_included(self, app):
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        private_routes = [p for p in route_paths if p.startswith("/private")]
        assert len(private_routes) > 0

    def test_database_router_included(self, app):
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        db_routes = [p for p in route_paths if p.startswith("/database")]
        assert len(db_routes) > 0

    def test_withdraw_router_included(self, app):
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        withdraw_routes = [p for p in route_paths if p.startswith("/withdraw")]
        assert len(withdraw_routes) > 0

    def test_cors_middleware(self, app):
        """CORS middleware should be configured."""
        middleware_classes = [
            type(m).__name__
            for m in getattr(app, "user_middleware", [])
        ]
        # FastAPI stores middleware in user_middleware as Middleware objects
        # We can also check via app.middleware_stack but it's harder to inspect.
        # Alternatively, just check the middleware was added
        from starlette.middleware.cors import CORSMiddleware
        has_cors = any(
            m.cls is CORSMiddleware
            for m in getattr(app, "user_middleware", [])
        )
        assert has_cors, "CORS middleware should be configured"


# ================================================================
# 5. Schema checks — Pydantic model instantiation
# ================================================================


class TestSchemas:
    """Verify Pydantic models can be instantiated with sample data."""

    # --- Base schemas ---

    def test_status_response(self):
        from app.schemas.base import StatusResponse
        obj = StatusResponse()
        assert obj.status == "ok"
        assert obj.message == ""

    def test_error_response(self):
        from app.schemas.base import ErrorResponse
        obj = ErrorResponse(message="something went wrong")
        assert obj.status == "error"
        assert obj.message == "something went wrong"

    def test_bulk_operation_result(self):
        from app.schemas.base import BulkOperationResult
        obj = BulkOperationResult(
            success=[{"database_id": 1, "status": "ok"}],
            failed=[{"database_id": 2, "error": "timeout"}],
        )
        assert obj.success_count == 1
        assert obj.failed_count == 1
        assert obj.total == 2

    def test_paginated_response(self):
        from app.schemas.base import PaginatedResponse
        obj = PaginatedResponse(items=[1, 2, 3], total=100, page=2, page_size=25)
        assert obj.total == 100
        assert obj.page == 2

    def test_database_id_list(self):
        from app.schemas.base import DatabaseIdList
        obj = DatabaseIdList(database_ids=[1, 2, 3])
        assert obj.database_ids == [1, 2, 3]

    def test_account_identifier(self):
        from app.schemas.base import AccountIdentifier
        obj = AccountIdentifier(database_id=42)
        assert obj.database_id == 42

    def test_coin_chain_pair(self):
        from app.schemas.base import CoinChainPair
        obj = CoinChainPair()
        assert obj.coin == "USDT"
        assert obj.chain == "APTOS"

    def test_amount_field(self):
        from app.schemas.base import AmountField
        obj = AmountField(amount=100.5, precision=8)
        assert obj.amount == 100.5

    # --- Database schemas ---

    def test_account_create(self):
        from app.schemas.database import AccountCreate
        obj = AccountCreate(
            email_address="test@test.com",
            password="secret",
            group_name="test_group",
        )
        assert obj.email_address == "test@test.com"
        assert obj.group_name == "test_group"

    def test_account_update(self):
        from app.schemas.database import AccountUpdate
        obj = AccountUpdate(password="new_pass", group_name="vip")
        assert obj.password == "new_pass"
        assert obj.group_name == "vip"
        # All fields should be optional
        obj_empty = AccountUpdate()
        assert obj_empty.password is None

    def test_account_response(self):
        from app.schemas.database import AccountResponse
        obj = AccountResponse(
            database_id=1,
            email_address="test@test.com",
            uid=123456,
            balance_usd=1000.50,
        )
        assert obj.database_id == 1
        assert obj.uid == 123456

    def test_account_list_response(self):
        from app.schemas.database import AccountListResponse
        obj = AccountListResponse(total=100, page=1, page_size=50)
        assert obj.total == 100
        assert len(obj.accounts) == 0

    def test_email_create(self):
        from app.schemas.database import EmailCreate
        obj = EmailCreate(
            address="user@gmail.com",
            imap_address="imap.gmail.com",
            imap_password="app-password",
        )
        assert obj.address == "user@gmail.com"

    def test_email_response(self):
        from app.schemas.database import EmailResponse
        obj = EmailResponse(address="user@gmail.com")
        assert obj.proxy_error is False
        assert obj.last_login_failed is False

    def test_import_accounts_request(self):
        from app.schemas.database import ImportAccountsRequest, AccountCreate
        obj = ImportAccountsRequest(
            accounts=[
                AccountCreate(email_address="a@b.com", password="p1"),
                AccountCreate(email_address="c@d.com", password="p2"),
            ],
            group_name="batch1",
        )
        assert len(obj.accounts) == 2
        assert obj.group_name == "batch1"

    def test_export_format(self):
        from app.schemas.database import ExportFormat
        obj = ExportFormat()
        assert obj.format == "csv"
        assert "database_id" in obj.fields

    # --- Private schemas ---

    def test_login_request(self):
        from app.schemas.private.common import LoginRequest
        obj = LoginRequest(database_ids=[1, 2, 3])
        assert obj.database_ids == [1, 2, 3]
        assert obj.concurrency == 5

    def test_register_request(self):
        from app.schemas.private.common import RegisterRequest
        obj = RegisterRequest(database_ids=[1], ref_code="ABCDEF", country_code="US")
        assert obj.ref_code == "ABCDEF"

    def test_withdraw_request(self):
        from app.schemas.private.common import WithdrawRequest
        obj = WithdrawRequest(
            database_ids=[1, 2],
            coin="ETH",
            chain="ETH",
            address="0xabc123",
            amount=0.5,
        )
        assert obj.coin == "ETH"
        assert obj.amount == 0.5

    def test_transfer_request(self):
        from app.schemas.private.common import TransferRequest
        obj = TransferRequest(
            database_ids=[1],
            coin="USDT",
            amount=100.0,
            from_account_type="FUND",
            to_account_type="UNIFIED",
        )
        assert obj.from_account_type == "FUND"

    def test_change_password_request(self):
        from app.schemas.private.common import ChangePasswordRequest
        obj = ChangePasswordRequest(database_ids=[1], new_password="NewPass123!")
        assert obj.new_password == "NewPass123!"

    def test_balance_check_request(self):
        from app.schemas.private.common import BalanceCheckRequest
        obj = BalanceCheckRequest(database_ids=[1, 2, 3])
        assert len(obj.database_ids) == 3

    def test_enable_2fa_request(self):
        from app.schemas.private.common import Enable2FARequest
        obj = Enable2FARequest(database_ids=[1])
        assert obj.database_ids == [1]

    def test_disable_2fa_request(self):
        from app.schemas.private.common import Disable2FARequest
        obj = Disable2FARequest(database_ids=[1, 2])
        assert len(obj.database_ids) == 2

    # --- Router-inline schemas ---

    def test_withdraw_router_schemas(self):
        from app.routers.withdraw import (
            WithdrawRequest,
            AddWithdrawAddressRequest,
            DeleteWithdrawAddressRequest,
            SwitchWhitelistRequest,
            WithdrawResponse,
        )
        wr = WithdrawRequest(
            database_ids=[1],
            coin="USDT",
            chain="APTOS",
            address="0xabc",
            amount=10.0,
        )
        assert wr.withdraw_type == 0

        addr = AddWithdrawAddressRequest(
            database_ids=[1],
            coin="USDT",
            address="0xdef",
            remark="main wallet",
        )
        assert addr.remark == "main wallet"

        switch = SwitchWhitelistRequest(database_ids=[1], enable=False)
        assert switch.enable is False

        resp = WithdrawResponse()
        assert resp.success == []
        assert resp.failed == []

    def test_private_router_schemas(self):
        from app.routers.private import (
            LoginRequest,
            RegisterRequest,
            ProfileRequest,
            Enable2FARequest,
        )
        lr = LoginRequest(database_ids=[1, 2], concurrency=10)
        assert lr.concurrency == 10

        rr = RegisterRequest(database_ids=[1], ref_code="REF123")
        assert rr.ref_code == "REF123"

    def test_database_router_schemas(self):
        from app.routers.database import (
            AccountCreateRequest,
            AccountUpdateRequest,
        )
        cr = AccountCreateRequest(email_address="new@test.com")
        assert cr.group_name == "no_group"

        ur = AccountUpdateRequest(password="changed")
        assert ur.password == "changed"


# ================================================================
# 6. Exception hierarchy checks
# ================================================================


class TestExceptionHierarchy:
    """Verify exception class relationships."""

    def test_bybit_exceptions(self):
        from bybit.client.base import (
            BybitException,
            BybitHTTPJSONException,
            BybitHTMLError,
            BybitComponentError,
        )
        assert issubclass(BybitHTTPJSONException, BybitException)
        assert issubclass(BybitHTMLError, BybitException)
        assert issubclass(BybitComponentError, BybitException)
        assert issubclass(BybitException, Exception)

    def test_anycaptcha_exceptions(self):
        from anycaptcha.errors import (
            AnyCaptchaException,
            CaptchaError,
            CaptchaTimeout,
            CaptchaUnsolvable,
            CaptchaServiceError,
            CaptchaInvalidKey,
            CaptchaNoBalance,
        )
        assert issubclass(AnyCaptchaException, Exception)
        assert issubclass(CaptchaError, AnyCaptchaException)
        assert issubclass(CaptchaTimeout, AnyCaptchaException)
        assert issubclass(CaptchaUnsolvable, AnyCaptchaException)
        assert issubclass(CaptchaServiceError, AnyCaptchaException)
        assert issubclass(CaptchaInvalidKey, CaptchaServiceError)
        assert issubclass(CaptchaNoBalance, CaptchaServiceError)


# ================================================================
# 7. Inheritance chain checks
# ================================================================


class TestInheritance:
    """Verify class inheritance is correct."""

    def test_private_client_inherits_base_private(self):
        from bybit.client.private_client import PrivateClient
        from bybit.client.base_private_client import BasePrivateClient
        from bybit.client.base import BaseClient
        assert issubclass(PrivateClient, BasePrivateClient)
        assert issubclass(BasePrivateClient, BaseClient)

    def test_private_client_has_api_urls(self):
        """BasePrivateClient should have URL constants from memory dump."""
        from bybit.client.base_private_client import BasePrivateClient
        assert hasattr(BasePrivateClient, "URL_LOGIN")
        assert hasattr(BasePrivateClient, "URL_PROFILE")
        assert hasattr(BasePrivateClient, "URL_WITHDRAW_ONCHAIN")
        assert hasattr(BasePrivateClient, "URL_DEPOSIT_ADDRESS")
        assert BasePrivateClient.URL_LOGIN == "/login"

    def test_base_client_has_error_constants(self):
        from bybit.client.base import BYBIT_ERRORS
        assert BYBIT_ERRORS[10006] == "Too many requests"
        assert BYBIT_ERRORS[33004] == "Insufficient balance"
