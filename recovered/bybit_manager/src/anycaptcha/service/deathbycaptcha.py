"""
DeathByCaptcha service implementation.
API: https://deathbycaptcha.com/api
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base import BaseService

logger = logging.getLogger("anycaptcha.service.deathbycaptcha")


class DeathByCaptchaService(BaseService):
    """deathbycaptcha.com captcha solving service."""

    BASE_URL = "http://api.dbcapi.me/api"
    SERVICE_NAME = "deathbycaptcha"

    def __init__(self, api_key: str, **kwargs):
        # DBC uses username:password format in api_key
        super().__init__(api_key, **kwargs)
        parts = api_key.split(":", 1)
        self.username = parts[0]
        self.password = parts[1] if len(parts) > 1 else ""

    async def create_task(self, task: Dict[str, Any]) -> str:
        session = await self._get_session()
        payload = {
            "authtoken": self.api_key,
            **task,
        }
        async with session.post(
            f"{self.BASE_URL}/captcha/new", json=payload
        ) as resp:
            data = await resp.json()
            return str(data.get("captcha", ""))

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        session = await self._get_session()
        async with session.get(
            f"{self.BASE_URL}/captcha/{task_id}"
        ) as resp:
            data = await resp.json()
            if data.get("text"):
                return {"solution": data["text"]}
            return None
