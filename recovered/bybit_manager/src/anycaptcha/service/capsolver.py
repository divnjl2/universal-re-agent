"""
CapSolver service implementation.
API: https://docs.capsolver.com/
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base import BaseService

logger = logging.getLogger("anycaptcha.service.capsolver")


class CapSolverService(BaseService):
    """capsolver.com captcha solving service."""

    BASE_URL = "https://api.capsolver.com"
    SERVICE_NAME = "capsolver"

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
                raise Exception(f"capsolver error: {data.get('errorDescription')}")
            return str(data["taskId"])

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        session = await self._get_session()
        payload = {
            "clientKey": self.api_key,
            "taskId": task_id,
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
