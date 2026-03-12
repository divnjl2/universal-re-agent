"""
2captcha service implementation.
API: https://2captcha.com/api-docs
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base import BaseService

logger = logging.getLogger("anycaptcha.service.twocaptcha")


class TwoCaptchaService(BaseService):
    """2captcha.com captcha solving service."""

    BASE_URL = "https://2captcha.com"
    SERVICE_NAME = "2captcha"

    async def create_task(self, task: Dict[str, Any]) -> str:
        session = await self._get_session()
        payload = {
            "clientKey": self.api_key,
            "task": task,
        }
        async with session.post(
            f"{self.BASE_URL}/createTask", json=payload
        ) as resp:
            data = await resp.json()
            if data.get("errorId", 0) != 0:
                raise Exception(f"2captcha error: {data.get('errorDescription')}")
            return str(data["taskId"])

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        session = await self._get_session()
        payload = {
            "clientKey": self.api_key,
            "taskId": int(task_id),
        }
        async with session.post(
            f"{self.BASE_URL}/getTaskResult", json=payload
        ) as resp:
            data = await resp.json()
            if data.get("status") == "ready":
                return data.get("solution", {})
            return None

    async def get_balance(self) -> float:
        session = await self._get_session()
        payload = {"clientKey": self.api_key}
        async with session.post(
            f"{self.BASE_URL}/getBalance", json=payload
        ) as resp:
            data = await resp.json()
            return float(data.get("balance", 0.0))
