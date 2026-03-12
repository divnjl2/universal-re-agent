"""
Bybit KYC API service — handles all Bybit API interactions for the KYC bot.

Real API endpoints from memory dump:
  https://api2.bybitglobal.com/v3/private/kyc/get-kyc-provider
  https://api2.bybitglobal.com/v3/private/kyc/get-verification-sdk-info
  https://api2.bybitglobal.com/v3/private/kyc/kyc-info
  https://api2.bybitglobal.com/v3/private/kyc/submit-questionnaire
  https://api2.bybitglobal.com/x-api/v3/private/kyc/kyc-personal-info
  https://www.bybitglobal.com/x-api/segw/awar/v1/awarding
  https://www.bybitglobal.com/x-api/segw/awar/v1/awarding/search-together
  https://www.bybitglobal.com/x-api/user/public/risk/face/token
  https://www.bybitglobal.com/x-api/user/public/risk/verify
  https://www.bybitglobal.com/x-api/v1/kyc-provider/callback
  https://www.bybitglobal.com/x-api/v1/kyc/face_auth/status
  https://www.bybitglobal.com/x-api/v3/private/kyc/need-confirm-pi

From memory classes:
  tg_bot.services.bybit.GetKycLink (dataclass at address 2186457298160)
  GetKycLinkid (field)
  GetKycLinkllable[str] (type annotation fragment -> Optional[str])
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import aiohttp

from tg_bot.config import config
from tg_bot.dto.service_result import ServiceResult, ServiceError

logger = logging.getLogger(__name__)

# Real Bybit API base URLs from memory dump
BYBIT_API_BASE = "https://api2.bybitglobal.com"
BYBIT_WEB_BASE = "https://www.bybitglobal.com"


@dataclass
class GetKycLink:
    """
    Result of getting a KYC verification link from Bybit.

    Fields recovered from memory: id, url (Optional[str]).
    """
    id: Optional[str] = None
    url: Optional[str] = None


class BybitKycService:
    """
    Bybit KYC API client.

    Uses cookies from bybit_account.cookies for authentication
    (no API key — uses session-based auth from web login).
    """

    def __init__(self, cookies: dict | None = None, proxy: str | None = None) -> None:
        self.cookies = cookies or {}
        self.proxy = proxy
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Referer": "https://www.bybitglobal.com/",
            "Origin": "https://www.bybitglobal.com",
        }

    def _make_cookie_jar(self) -> aiohttp.CookieJar:
        """Build aiohttp CookieJar from stored cookies dict."""
        jar = aiohttp.CookieJar(unsafe=True)
        for name, value in self.cookies.items():
            jar.update_cookies({name: str(value)})
        return jar

    async def get_kyc_provider(self) -> ServiceResult[dict]:
        """
        GET /v3/private/kyc/get-kyc-provider

        Returns the KYC provider assigned to this account (SumSub/Onfido/AAI).
        """
        url = f"{BYBIT_API_BASE}/v3/private/kyc/get-kyc-provider"
        return await self._request("GET", url)

    async def get_kyc_info(self) -> ServiceResult[dict]:
        """
        GET /v3/private/kyc/kyc-info

        Returns current KYC verification status and details.
        """
        url = f"{BYBIT_API_BASE}/v3/private/kyc/kyc-info"
        return await self._request("GET", url)

    async def get_verification_sdk_info(self) -> ServiceResult[dict]:
        """
        GET /v3/private/kyc/get-verification-sdk-info

        Returns SDK initialization data for the KYC provider (SumSub token, etc.).
        """
        url = f"{BYBIT_API_BASE}/v3/private/kyc/get-verification-sdk-info"
        return await self._request("GET", url)

    async def get_personal_info(self) -> ServiceResult[dict]:
        """
        GET /x-api/v3/private/kyc/kyc-personal-info

        Returns the user's submitted personal info for KYC.
        """
        url = f"{BYBIT_API_BASE}/x-api/v3/private/kyc/kyc-personal-info"
        return await self._request("GET", url)

    async def need_confirm_pi(self) -> ServiceResult[dict]:
        """
        GET /x-api/v3/private/kyc/need-confirm-pi

        Check if personal info needs confirmation.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/v3/private/kyc/need-confirm-pi"
        return await self._request("GET", url)

    async def submit_questionnaire(self, answers: dict) -> ServiceResult[dict]:
        """
        POST /v3/private/kyc/submit-questionnaire

        Submit KYC questionnaire answers.
        """
        url = f"{BYBIT_API_BASE}/v3/private/kyc/submit-questionnaire"
        return await self._request("POST", url, json_data=answers)

    async def kyc_provider_callback(self, data: dict) -> ServiceResult[dict]:
        """
        POST /x-api/v1/kyc-provider/callback

        Callback to Bybit after KYC provider (SumSub) completes verification.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/v1/kyc-provider/callback"
        return await self._request("POST", url, json_data=data)

    # --- Face verification ---

    async def get_face_token(self) -> ServiceResult[dict]:
        """
        GET /x-api/user/public/risk/face/token

        Get a token to initiate face verification.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/user/public/risk/face/token"
        return await self._request("GET", url)

    async def check_face_auth_status(self, ticket: str) -> ServiceResult[dict]:
        """
        GET /x-api/v1/kyc/face_auth/status?ticket=<ticket>

        From memory:
          https://www.bybitglobal.com/x-api/v1/kyc/face_auth/status?ticket=new-tkt_27685769-...
        """
        url = f"{BYBIT_WEB_BASE}/x-api/v1/kyc/face_auth/status"
        return await self._request("GET", url, params={"ticket": ticket})

    async def risk_verify(self, data: dict) -> ServiceResult[dict]:
        """
        POST /x-api/user/public/risk/verify

        Submit risk verification data.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/user/public/risk/verify"
        return await self._request("POST", url, json_data=data)

    # --- Awards ---

    async def get_awards(self) -> ServiceResult[dict]:
        """
        GET /x-api/segw/awar/v1/awarding

        Fetch available awards/rewards for the account.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/segw/awar/v1/awarding"
        return await self._request("GET", url)

    async def search_awards(self, params: dict | None = None) -> ServiceResult[dict]:
        """
        GET /x-api/segw/awar/v1/awarding/search-together

        Search/list all awards with filtering.
        """
        url = f"{BYBIT_WEB_BASE}/x-api/segw/awar/v1/awarding/search-together"
        return await self._request("GET", url, params=params)

    # --- Internal request helper ---

    async def _request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        json_data: Any = None,
    ) -> ServiceResult[dict]:
        """Execute an HTTP request with session cookies and optional proxy."""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(
                cookies=self.cookies,
                timeout=timeout,
            ) as session:
                kwargs: dict[str, Any] = {"headers": self._headers}
                if params:
                    kwargs["params"] = params
                if json_data is not None:
                    kwargs["json"] = json_data
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.request(method, url, **kwargs) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.warning(
                            "Bybit API %s %s -> %d: %s",
                            method, url, resp.status, body[:200],
                        )
                        return ServiceResult.fail(
                            ServiceError(code=str(resp.status), message=body[:200])
                        )

                    data = await resp.json()
                    # Bybit API wraps responses in {"ret_code": 0, "ret_msg": "success", "result": ..., "ext_code": "", "ext_info": null, "time_now": "..."}
                    ret_code = data.get("ret_code", data.get("retCode", 0))
                    if ret_code != 0:
                        return ServiceResult.fail(
                            ServiceError(
                                code=str(ret_code),
                                message=data.get("ret_msg", data.get("retMsg", "Unknown")),
                            )
                        )
                    return ServiceResult.ok(data.get("result", data))

        except aiohttp.ClientError as e:
            logger.exception("Bybit API request failed: %s %s", method, url)
            return ServiceResult.fail(ServiceError(code="NETWORK", message=str(e)))
        except Exception as e:
            logger.exception("Unexpected error in Bybit API: %s", e)
            return ServiceResult.fail(ServiceError(code="INTERNAL", message=str(e)))
