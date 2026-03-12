"""
Bybit HTTP client base — recovered from Nuitka binary + memory dump analysis.
Provides the core async HTTP session management, cookie handling, proxy support,
and Bybit-specific error handling used by all client classes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

import aiohttp
from aiohttp import ClientResponse, ClientTimeout, TCPConnector

logger = logging.getLogger("bybit.client.base")

# ============================================================
# Constants recovered from binary + memory dump
# ============================================================

BASE_URL = "https://api2.bybitglobal.com"

API_DOMAINS: Dict[str, str] = {
    "global": "api2.bybitglobal.com",
    "public": "api.bybitglobal.com",
    "www": "www.bybitglobal.com",
    "com": "api2.bybit.com",
    "eu": "api2.bybit.eu",
    "kz": "api2.bybit.kz",
    "tr": "api2.bybit.tr",
    "georgia": "api2.bybitgeorgia.ge",
    "id": "api2.bybit-global.com",
}

RECAPTCHA_SITE_KEY = "6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6"

COOKIE_NAMES = [
    "_by_l_g_d",
    "sensorsdata2015jssdkcross",
    "deviceId",
    "BYBIT_REG_REF_prod",
    "EO-Bot-Session",
    "EO-Bot-SessionId",
    "EO-Bot-Token",
    "self-unbind-token",
    "secure-token",
    "isLogin",
    "sajssdk_2015_cross_new_user",
    "_tt_enable_cookie",
]

# Multi-locale login URLs (22 locales recovered from memory)
LOGIN_LOCALES: Dict[str, str] = {
    "en": "www.bybitglobal.com",
    "ru-RU": "www.bybit.com",
    "ar-SA": "www.bybit.com",
    "ja-JP": "www.bybit.com",
    "pt-BR": "www.bybit.com",
    "es-ES": "www.bybit.com",
    "es-MX": "www.bybit.com",
    "es-AR": "www.bybit.com",
    "vi-VN": "www.bybit.com",
    "zh-TW": "www.bybit.com",
    "uk-UA": "www.bybit.com",
    "en-GB": "www.bybit.com",
    "pt-PT": "www.bybit.com",
    "zh-MY": "www.bybitglobal.com",
    "id-ID": "www.bybit-global.com",
    "cs-EU": "www.bybit.eu",
    "da-EU": "www.bybit.eu",
    "de-EU": "www.bybit.eu",
    "el-EU": "www.bybit.eu",
    "en-EU": "www.bybit.eu",
    "es-EU": "www.bybit.eu",
    "fi-EU": "www.bybit.eu",
    "fr-EU": "www.bybit.eu",
    "hu-EU": "www.bybit.eu",
    "it-EU": "www.bybit.eu",
    "lt-EU": "www.bybit.eu",
    "nl-EU": "www.bybit.eu",
    "no-EU": "www.bybit.eu",
    "pl-EU": "www.bybit.eu",
    "pt-EU": "www.bybit.eu",
    "ro-EU": "www.bybit.eu",
    "sv-EU": "www.bybit.eu",
    "en-KAZ": "www.bybit.kz",
    "kk-KAZ": "www.bybit.kz",
    "ru-KAZ": "www.bybit.kz",
    "en-TR": "www.bybit.tr",
    "tr-TUR": "www.bybit.tr",
    "en-GEO": "www.bybitgeorgia.ge",
    "ka-GEO": "www.bybitgeorgia.ge",
    "ru-GEO": "www.bybitgeorgia.ge",
}

# Error code constants recovered from memory
BYBIT_ERRORS: Dict[int, str] = {
    0: "OK",
    10001: "Parameter error",
    10002: "Internal error",
    10003: "Invalid request",
    10004: "Invalid sign",
    10005: "Permission denied",
    10006: "Too many requests",
    10010: "Unrecognized request",
    20001: "User not found",
    20006: "Two-factor auth required",
    20072: "Account banned",
    33004: "Insufficient balance",
    34036: "Withdraw suspended",
    34037: "Withdraw address not in whitelist",
    131001: "KYC required",
}

BYBIT_COMPONENT_ERROR = "component_error"
BYBIT_HTML_ERROR = "html_error"
BYBIT_JSON_ERROR = "json_error"

# DB column name constants (used by manager)
BYBIT_COOKIES_COLUMN = "cookies"
BYBIT_COUNTRY_CODE_COLUMN = "last_login_country_code"
BYBIT_PASSWORD_COLUMN = "password"
BYBIT_PROXY_COLUMN = "proxy"
BYBIT_TOTP_SECRET_COLUMN = "totp_secret"
BYBIT_MNEMONIC_PHRASE = "web3_mnemonic_phrase"
BYBIT_INVITER_REF_CODE = "inviter_ref_code"

# Card / pay constants
BYBIT_CARD = "BYBIT_CARD"
BYBIT_CARD_DEFAULT = "BYBIT_CARD_DEFAULT"
BYBIT_PAY = "BYBIT_PAY"


class BybitException(Exception):
    """Base Bybit API exception."""

    def __init__(self, ret_code: int = 0, ret_msg: str = "", ext_info: Any = None):
        self.ret_code = ret_code
        self.ret_msg = ret_msg
        self.ext_info = ext_info or {}
        super().__init__(f"[{ret_code}] {ret_msg}")


class BybitHTTPJSONException(BybitException):
    """Exception raised when Bybit returns a JSON error response."""
    pass


class BybitHTMLError(BybitException):
    """Exception raised when Bybit returns an HTML error page (rate limit, WAF, etc.)."""
    pass


class BybitComponentError(BybitException):
    """Exception raised when a risk verification component is required."""

    def __init__(self, ret_code: int, ret_msg: str, ext_info: Any = None,
                 risk_token: str = "", challenges: Optional[List[Dict]] = None):
        super().__init__(ret_code, ret_msg, ext_info)
        self.risk_token = risk_token
        self.challenges = challenges or []


class BybitResponse:
    """Parsed Bybit API response wrapper."""

    def __init__(self, ret_code: int, ret_msg: str, result: Any = None,
                 ext_info: Any = None, time_now: Optional[str] = None):
        self.ret_code = ret_code
        self.ret_msg = ret_msg
        self.result = result
        self.ext_info = ext_info or {}
        self.time_now = time_now

    @property
    def ok(self) -> bool:
        return self.ret_code == 0

    def __repr__(self) -> str:
        return f"BybitResponse(ret_code={self.ret_code}, ret_msg={self.ret_msg!r})"


class BybitDevice:
    """Device fingerprint data for browser-like API requests."""

    def __init__(
        self,
        device_id: Optional[str] = None,
        chrome_major_version: int = 135,
        os: str = "Windows",
        screen_width: int = 1920,
        screen_height: int = 1080,
    ):
        self.device_id = device_id or str(uuid.uuid4())
        self.chrome_major_version = chrome_major_version
        self.os = os
        self.screen_width = screen_width
        self.screen_height = screen_height

    @property
    def user_agent(self) -> str:
        return (
            f"Mozilla/5.0 ({self.os}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{self.chrome_major_version}.0.0.0 Safari/537.36"
        )

    @property
    def sec_ch_ua(self) -> str:
        return (
            f'"Chromium";v="{self.chrome_major_version}", '
            f'"Google Chrome";v="{self.chrome_major_version}", '
            f'"Not-A.Brand";v="99"'
        )


class BybitCardCommission:
    """Bybit card commission info model."""

    def __init__(self, coin: str = "", chain: str = "", fee: float = 0.0,
                 min_amount: float = 0.0, max_amount: float = 0.0):
        self.coin = coin
        self.chain = chain
        self.fee = fee
        self.min_amount = min_amount
        self.max_amount = max_amount


class BaseClient:
    """
    Async HTTP client base for Bybit web API.

    Uses browser-like requests with cookies, device fingerprinting, and
    proxy support. NOT the official REST API — uses internal web endpoints
    at api2.bybitglobal.com.
    """

    DEFAULT_TIMEOUT = ClientTimeout(total=30, connect=10)
    MAX_RETRIES = 3

    def __init__(
        self,
        proxy: Optional[str] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        device: Optional[BybitDevice] = None,
        base_url: str = BASE_URL,
        locale: str = "en",
        timeout: Optional[ClientTimeout] = None,
    ):
        self.proxy = proxy
        self._raw_cookies = cookies or []
        self.device = device or BybitDevice()
        self.base_url = base_url
        self.locale = locale
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self._session: Optional[aiohttp.ClientSession] = None
        self._guid: Optional[str] = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Create or return the aiohttp session with proper headers and cookies."""
        if self._session is None or self._session.closed:
            connector = TCPConnector(ssl=False, limit=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=self._build_default_headers(),
            )
            # Load cookies from stored cookie list
            if self._raw_cookies:
                self._load_cookies(self._raw_cookies)
        return self._session

    def _build_default_headers(self) -> Dict[str, str]:
        """Build browser-like request headers."""
        return {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "platform": "pc",
            "lang": "en-US",
            "origin": "https://www.bybitglobal.com",
            "referer": "https://www.bybitglobal.com/",
            "sec-ch-ua": self.device.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{self.device.os}"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "priority": "u=1, i",
            "user-agent": self.device.user_agent,
        }

    @staticmethod
    def _generate_traceparent() -> str:
        """Generate W3C traceparent header: 00-{trace_id}-{parent_id}-{flags}."""
        trace_id = hashlib.md5(uuid.uuid4().bytes).hexdigest()
        parent_id = hashlib.md5(uuid.uuid4().bytes).hexdigest()[:16]
        return f"00-{trace_id}-{parent_id}-00"

    def _load_cookies(self, cookies: List[Dict[str, Any]]) -> None:
        """Load cookies from Bybit cookie list format into session."""
        if self._session is None:
            return
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            domain = cookie.get("domain", ".bybitglobal.com")
            if name and value:
                self._session.cookie_jar.update_cookies(
                    {name: value},
                    response_url=aiohttp.client.URL(f"https://{domain.lstrip('.')}/"),
                )

    def export_cookies(self) -> List[Dict[str, Any]]:
        """Export current session cookies in Bybit's format."""
        cookies = []
        if self._session:
            for cookie in self._session.cookie_jar:
                cookies.append({
                    "name": cookie.key,
                    "value": cookie.value,
                    "domain": cookie.get("domain", ".bybitglobal.com"),
                    "path": cookie.get("path", "/"),
                    "secure": cookie.get("secure", "") == "true",
                    "httpOnly": cookie.get("httponly", "") == "true",
                })
        return cookies

    @property
    def guid(self) -> str:
        """Get or generate the request GUID."""
        if self._guid is None:
            self._guid = str(uuid.uuid4())
        return self._guid

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retry: int = 0,
    ) -> BybitResponse:
        """
        Core request method with retry logic, error parsing, and proxy support.

        Handles:
        - JSON error responses (BybitHTTPJSONException)
        - HTML error pages / WAF blocks (BybitHTMLError)
        - Component/risk verification challenges (BybitComponentError)
        - Automatic retry on transient failures
        """
        session = await self._ensure_session()

        # Build full URL if relative path
        if url.startswith("/"):
            url = f"{self.base_url}{url}"

        extra_headers = dict(headers or {})
        extra_headers["guid"] = self.guid
        extra_headers["traceparent"] = self._generate_traceparent()

        request_kwargs: Dict[str, Any] = {
            "headers": extra_headers,
        }
        if json_data is not None:
            request_kwargs["json"] = json_data
        if params is not None:
            request_kwargs["params"] = params
        if self.proxy:
            request_kwargs["proxy"] = self.proxy

        try:
            async with session.request(method, url, **request_kwargs) as resp:
                return await self._parse_response(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if retry < self.MAX_RETRIES:
                wait = (retry + 1) * 2 + random.random()
                logger.warning(
                    "Request failed (%s), retrying in %.1fs: %s %s",
                    type(e).__name__, wait, method, url,
                )
                await asyncio.sleep(wait)
                return await self._request(
                    method, url, json_data=json_data, params=params,
                    headers=headers, retry=retry + 1,
                )
            raise BybitException(ret_code=-1, ret_msg=f"Request failed: {e}")

    async def _parse_response(self, resp: ClientResponse) -> BybitResponse:
        """Parse Bybit API response, raising appropriate exceptions."""
        content_type = resp.content_type or ""

        if "text/html" in content_type:
            text = await resp.text()
            raise BybitHTMLError(
                ret_code=resp.status,
                ret_msg=f"HTML error response (status {resp.status})",
                ext_info={"html": text[:500]},
            )

        try:
            data = await resp.json()
        except Exception:
            text = await resp.text()
            raise BybitHTTPJSONException(
                ret_code=resp.status,
                ret_msg=f"Invalid JSON response: {text[:200]}",
            )

        ret_code = data.get("ret_code", data.get("retCode", 0))
        ret_msg = data.get("ret_msg", data.get("retMsg", ""))
        result = data.get("result", data.get("data"))
        ext_info = data.get("ext_info", data.get("extInfo", {}))
        time_now = data.get("time_now", data.get("time"))

        # Check for component/risk challenge
        if ret_code != 0 and isinstance(ext_info, dict):
            risk_token = ext_info.get("riskToken", ext_info.get("risk_token", ""))
            challenges = ext_info.get("challenges", ext_info.get("verifyParam", []))
            if risk_token or challenges:
                raise BybitComponentError(
                    ret_code=ret_code,
                    ret_msg=ret_msg,
                    ext_info=ext_info,
                    risk_token=risk_token,
                    challenges=challenges if isinstance(challenges, list) else [],
                )

        if ret_code != 0:
            raise BybitHTTPJSONException(
                ret_code=ret_code,
                ret_msg=ret_msg,
                ext_info=ext_info,
            )

        return BybitResponse(
            ret_code=ret_code,
            ret_msg=ret_msg,
            result=result,
            ext_info=ext_info,
            time_now=time_now,
        )

    async def get(self, url: str, params: Optional[Dict] = None,
                  headers: Optional[Dict] = None) -> BybitResponse:
        return await self._request("GET", url, params=params, headers=headers)

    async def post(self, url: str, json_data: Optional[Dict] = None,
                   params: Optional[Dict] = None,
                   headers: Optional[Dict] = None) -> BybitResponse:
        return await self._request("POST", url, json_data=json_data,
                                   params=params, headers=headers)

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        await self._ensure_session()
        return self

    async def __aexit__(self, *args):
        await self.close()
