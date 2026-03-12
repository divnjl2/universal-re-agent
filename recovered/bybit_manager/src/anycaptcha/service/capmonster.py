"""
CapMonster.cloud captcha service — async client.

API endpoints from memory dump:
- https://api.capmonster.cloud/createTask
- https://api.capmonster.cloud/getTaskResult
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import aiohttp

from ..captcha.base import BaseCaptcha, BaseCaptchaSolution
from ..captcha.recaptcha_v2 import RecaptchaV2, RecaptchaV2Solution
from ..captcha.geetest import GeeTest, GeeTestSolution
from ..captcha.geetest_v4 import GeeTestV4, GeeTestV4Solution
from ..errors import (
    AnyCaptchaException,
    CaptchaError,
    CaptchaTimeout,
    CaptchaNoBalance,
    CaptchaServiceError,
)

logger = logging.getLogger("anycaptcha.service.capmonster")

BASE_URL = "https://api.capmonster.cloud"


class CapMonsterService:
    """
    Async CapMonster.cloud captcha solving service.

    Usage:
        service = CapMonsterService(api_key="your_key")
        task = RecaptchaV2(site_key="...", page_url="...")
        result = await service.solve(task)
    """

    def __init__(self, api_key: str, base_url: str = BASE_URL):
        self.api_key = api_key
        self.base_url = base_url
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    def _build_task(self, captcha: BaseCaptcha) -> Dict[str, Any]:
        """Build CapMonster task payload from captcha definition."""
        task: Dict[str, Any] = {}

        if isinstance(captcha, RecaptchaV2):
            task["type"] = "RecaptchaV2TaskProxyless" if not captcha.proxy else "RecaptchaV2Task"
            task["websiteURL"] = captcha.page_url
            task["websiteKey"] = captcha.site_key
            if captcha.invisible:
                task["isInvisible"] = True
            if captcha.enterprise:
                task["isEnterprise"] = True

        elif isinstance(captcha, GeeTest):
            task["type"] = "GeeTestTaskProxyless" if not captcha.proxy else "GeeTestTask"
            task["websiteURL"] = captcha.page_url
            task["gt"] = captcha.gt
            task["challenge"] = captcha.challenge
            if captcha.api_server:
                task["geetestApiServerSubdomain"] = captcha.api_server

        elif isinstance(captcha, GeeTestV4):
            task["type"] = "RecaptchaV2TaskProxyless"  # CapMonster maps GeeTest v4 differently
            task["type"] = "GeeTestTaskProxyless" if not captcha.proxy else "GeeTestTask"
            task["websiteURL"] = captcha.page_url
            task["gt"] = captcha.captcha_id
            task["version"] = 4

        else:
            raise AnyCaptchaException(f"Unsupported captcha type: {type(captcha).__name__}")

        # Add proxy info if present
        if captcha.proxy:
            proxy_parts = captcha.proxy.replace("http://", "").replace("https://", "")
            if "@" in proxy_parts:
                auth, host = proxy_parts.split("@", 1)
                login, password = auth.split(":", 1)
                host_parts = host.split(":")
                task["proxyType"] = captcha.proxy_type
                task["proxyAddress"] = host_parts[0]
                task["proxyPort"] = int(host_parts[1]) if len(host_parts) > 1 else 80
                task["proxyLogin"] = login
                task["proxyPassword"] = password
            else:
                host_parts = proxy_parts.split(":")
                task["proxyType"] = captcha.proxy_type
                task["proxyAddress"] = host_parts[0]
                task["proxyPort"] = int(host_parts[1]) if len(host_parts) > 1 else 80

        if captcha.user_agent:
            task["userAgent"] = captcha.user_agent

        return task

    async def create_task(self, captcha: BaseCaptcha) -> str:
        """Create a captcha solving task. Returns task_id."""
        session = await self._ensure_session()
        payload = {
            "clientKey": self.api_key,
            "task": self._build_task(captcha),
        }

        async with session.post(f"{self.base_url}/createTask", json=payload) as resp:
            data = await resp.json()

        error_id = data.get("errorId", 0)
        if error_id != 0:
            error_code = data.get("errorCode", "")
            error_desc = data.get("errorDescription", "")
            if "KEY" in error_code or "AUTHORIZATION" in error_code:
                raise CaptchaServiceError(f"Auth error: {error_code} {error_desc}")
            if "BALANCE" in error_code.upper() or "ZERO" in error_code.upper():
                raise CaptchaNoBalance(f"No balance: {error_code} {error_desc}")
            raise CaptchaError(f"CreateTask failed: {error_code} {error_desc}")

        task_id = data.get("taskId", "")
        if not task_id:
            raise CaptchaError("No taskId in response")

        return str(task_id)

    async def get_result(self, task_id: str) -> Dict[str, Any]:
        """Get task result. Returns solution dict or raises."""
        session = await self._ensure_session()
        payload = {
            "clientKey": self.api_key,
            "taskId": task_id,
        }

        async with session.post(f"{self.base_url}/getTaskResult", json=payload) as resp:
            data = await resp.json()

        error_id = data.get("errorId", 0)
        if error_id != 0:
            error_code = data.get("errorCode", "")
            raise CaptchaError(f"GetResult failed: {error_code}")

        status = data.get("status", "")
        if status == "ready":
            return data.get("solution", {})
        elif status == "processing":
            return {}
        else:
            raise CaptchaError(f"Unknown status: {status}")

    async def solve(
        self,
        captcha: BaseCaptcha,
        timeout: int = 180,
        poll_interval: int = 5,
    ) -> BaseCaptchaSolution:
        """Solve a captcha task (create + poll until ready or timeout)."""
        task_id = await self.create_task(captcha)
        logger.debug("CapMonster task created: %s", task_id)

        elapsed = 0
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            solution = await self.get_result(task_id)
            if solution:
                return BaseCaptchaSolution(solution=solution, task_id=task_id)

        raise CaptchaTimeout(f"Timeout after {timeout}s for task {task_id}")

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
