"""
SumSub KYC verification service — direct API integration.

Real endpoints from memory dump:
  https://direct-api.sumsub.com/resources/applicantActions/
  https://direct-api.sumsub.com/resources/applicants/
  https://direct-api.sumsub.com/resources/auth/-/isLoggedInByAccessToken
  https://direct-api.sumsub.com/resources/checks/latest?type=IP_CHECK&applicantId=
  https://direct-api.sumsub.com/resources/inspections/
  https://direct-api.sumsub.com/resources/sdkIntegrations/levels/curWebsdkLink
  https://direct-api.sumsub.com/resources/sdkIntegrations/websdkInit

SumSub bypass API (from api.sumsubio.com):
  https://api.sumsubio.com/api/create_bypass_by_token
  https://api.sumsubio.com/api/check_seller/335173721
  https://api.sumsubio.com/api/report_seller

Custom SumSub domains from memory (CDN/proxy):
  https://449-jk8.sumsubio.com/sumsub2
  https://468-x3.sumsubio.com/sumsub2
  https://469-8q.sumsubio.com/sumsub2
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

import aiohttp

from tg_bot.config import config
from tg_bot.dto.service_result import ServiceResult, ServiceError

logger = logging.getLogger(__name__)

# Real SumSub API URL from memory (direct-api, not the standard api.sumsub.com)
SUMSUB_API_URL = "https://direct-api.sumsub.com"

# SumSub bypass API (separate service)
SUMSUBIO_API_URL = "https://api.sumsubio.com"


class SumSubService:
    """
    Client for the SumSub identity verification API.

    Uses HMAC-SHA256 request signing with the app token and secret key.
    The PRIVATE_KEY from config is the SumSub secret key.
    """

    def __init__(self, proxy: str | None = None) -> None:
        self.secret_key: str = config.tgbot.PRIVATE_KEY or ""
        self.proxy = proxy

        # Support custom SumSub domain (e.g. "449-jk8.sumsubio.com")
        if config.tgbot.CUSTOM_SUMSUB_DOMAIN:
            self.base_url = f"https://{config.tgbot.CUSTOM_SUMSUB_DOMAIN}"
        else:
            self.base_url = SUMSUB_API_URL

    def _sign_request(
        self,
        method: str,
        url_path: str,
        timestamp: int,
        body: bytes = b"",
    ) -> str:
        """Generate HMAC-SHA256 signature for SumSub API."""
        message = f"{timestamp}{method.upper()}{url_path}".encode() + body
        return hmac.new(
            self.secret_key.encode(),
            message,
            hashlib.sha256,
        ).hexdigest()

    def _auth_headers(
        self,
        method: str,
        url_path: str,
        body: bytes = b"",
    ) -> dict[str, str]:
        """Build SumSub authentication headers."""
        ts = int(time.time())
        sig = self._sign_request(method, url_path, ts, body)
        return {
            "X-App-Token": self.secret_key,
            "X-App-Access-Ts": str(ts),
            "X-App-Access-Sig": sig,
            "Content-Type": "application/json",
        }

    async def create_applicant(
        self,
        external_user_id: str,
        level_name: str = "basic-kyc-level",
    ) -> ServiceResult[dict]:
        """
        POST /resources/applicants

        Create a new applicant in SumSub.
        """
        url_path = "/resources/applicants"
        payload = json.dumps({
            "externalUserId": external_user_id,
            "levelName": level_name,
        }).encode()

        headers = self._auth_headers("POST", url_path, payload)

        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {"headers": headers, "data": payload}
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.post(
                    f"{self.base_url}{url_path}", **kwargs
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200 or resp.status == 201:
                        logger.info("Created SumSub applicant: %s", data.get("id"))
                        return ServiceResult.ok(data)
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(data))
                    )
        except Exception as e:
            logger.exception("SumSub create_applicant failed")
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def get_applicant_status(self, applicant_id: str) -> ServiceResult[dict]:
        """
        GET /resources/applicants/<id>/requiredIdDocsStatus

        Get verification status for an applicant.
        """
        url_path = f"/resources/applicants/{applicant_id}/requiredIdDocsStatus"
        return await self._get(url_path)

    async def get_applicant_actions(self, applicant_id: str) -> ServiceResult[dict]:
        """
        GET /resources/applicantActions/?applicantId=<id>

        From memory: /resources/applicantActions/
        """
        url_path = f"/resources/applicantActions/?applicantId={applicant_id}"
        return await self._get(url_path)

    async def get_inspections(self, applicant_id: str) -> ServiceResult[dict]:
        """
        GET /resources/inspections/<applicant_id>

        From memory: /resources/inspections/
        """
        url_path = f"/resources/inspections/{applicant_id}"
        return await self._get(url_path)

    async def check_ip(self, applicant_id: str) -> ServiceResult[dict]:
        """
        GET /resources/checks/latest?type=IP_CHECK&applicantId=<id>

        From memory: /resources/checks/latest?type=IP_CHECK?applicantId=
        """
        url_path = f"/resources/checks/latest?type=IP_CHECK&applicantId={applicant_id}"
        return await self._get(url_path)

    async def is_logged_in(self, access_token: str) -> ServiceResult[dict]:
        """
        GET /resources/auth/-/isLoggedInByAccessToken

        Check if a SumSub access token is still valid.
        """
        url_path = "/resources/auth/-/isLoggedInByAccessToken"
        return await self._get(url_path)

    async def get_websdk_link(
        self,
        level_name: str = "basic-kyc-level",
        external_user_id: str = "",
        ttl: int = 1800,
    ) -> ServiceResult[str]:
        """
        POST /resources/sdkIntegrations/levels/curWebsdkLink

        Generate a web SDK verification link.
        From memory: /resources/sdkIntegrations/levels/curWebsdkLink
        """
        url_path = f"/resources/sdkIntegrations/levels/{level_name}/websdkLink"
        params = f"?ttlInSecs={ttl}&externalUserId={external_user_id}"

        headers = self._auth_headers("POST", url_path + params)

        try:
            async with aiohttp.ClientSession() as session:
                kwargs: dict[str, Any] = {"headers": headers}
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.post(
                    f"{self.base_url}{url_path}{params}", **kwargs
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        return ServiceResult.ok(data.get("url", ""))
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(data))
                    )
        except Exception as e:
            logger.exception("SumSub get_websdk_link failed")
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def websdk_init(self, data: dict) -> ServiceResult[dict]:
        """
        POST /resources/sdkIntegrations/websdkInit

        Initialize the web SDK session.
        From memory: /resources/sdkIntegrations/websdkInit
        """
        url_path = "/resources/sdkIntegrations/websdkInit"
        body = json.dumps(data).encode()
        headers = self._auth_headers("POST", url_path, body)

        try:
            async with aiohttp.ClientSession() as session:
                kwargs: dict[str, Any] = {"headers": headers, "data": body}
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.post(
                    f"{self.base_url}{url_path}", **kwargs
                ) as resp:
                    result = await resp.json()
                    if resp.status == 200:
                        return ServiceResult.ok(result)
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(result))
                    )
        except Exception as e:
            logger.exception("SumSub websdk_init failed")
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def reset_applicant(self, applicant_id: str) -> ServiceResult[bool]:
        """Reset an applicant for re-verification."""
        url_path = f"/resources/applicants/{applicant_id}/reset"
        headers = self._auth_headers("POST", url_path)

        try:
            async with aiohttp.ClientSession() as session:
                kwargs: dict[str, Any] = {"headers": headers}
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.post(
                    f"{self.base_url}{url_path}", **kwargs
                ) as resp:
                    if resp.status == 200:
                        return ServiceResult.ok(True)
                    body = await resp.text()
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=body[:200])
                    )
        except Exception as e:
            logger.exception("SumSub reset_applicant failed")
            return ServiceResult.fail(ServiceError(message=str(e)))

    # --- Bypass API (sumsubio.com) ---

    async def create_bypass(self, token: str) -> ServiceResult[dict]:
        """
        POST https://api.sumsubio.com/api/create_bypass_by_token

        From memory: /api/create_bypass_by_token
        """
        url = f"{SUMSUBIO_API_URL}/api/create_bypass_by_token"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"token": token},
                    proxy=self.proxy,
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        return ServiceResult.ok(data)
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(data))
                    )
        except Exception as e:
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def create_onfido_bypass(self, token: str) -> ServiceResult[dict]:
        """
        POST /api/create_onfido_bypass_by_token

        From memory: /api/create_onfido_bypass_by_token
        """
        url = f"{SUMSUBIO_API_URL}/api/create_onfido_bypass_by_token"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"token": token},
                    proxy=self.proxy,
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        return ServiceResult.ok(data)
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(data))
                    )
        except Exception as e:
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def check_seller(self, seller_id: int) -> ServiceResult[dict]:
        """
        GET /api/check_seller/<seller_id>

        From memory: /api/check_seller/335173721
        """
        url = f"{SUMSUBIO_API_URL}/api/check_seller/{seller_id}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, proxy=self.proxy) as resp:
                    data = await resp.json()
                    return ServiceResult.ok(data)
        except Exception as e:
            return ServiceResult.fail(ServiceError(message=str(e)))

    async def report_seller(self, data: dict) -> ServiceResult[dict]:
        """
        POST /api/report_seller

        From memory: /api/report_seller
        """
        url = f"{SUMSUBIO_API_URL}/api/report_seller"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, proxy=self.proxy) as resp:
                    result = await resp.json()
                    return ServiceResult.ok(result)
        except Exception as e:
            return ServiceResult.fail(ServiceError(message=str(e)))

    # --- Internal helper ---

    async def _get(self, url_path: str) -> ServiceResult[dict]:
        """Generic authenticated GET request."""
        headers = self._auth_headers("GET", url_path)
        try:
            async with aiohttp.ClientSession() as session:
                kwargs: dict[str, Any] = {"headers": headers}
                if self.proxy:
                    kwargs["proxy"] = self.proxy

                async with session.get(
                    f"{self.base_url}{url_path}", **kwargs
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        return ServiceResult.ok(data)
                    return ServiceResult.fail(
                        ServiceError(code=str(resp.status), message=str(data))
                    )
        except Exception as e:
            logger.exception("SumSub GET %s failed", url_path)
            return ServiceResult.fail(ServiceError(message=str(e)))
