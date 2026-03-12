"""
Base captcha service — abstract interface for all captcha solving services.
"""

from __future__ import annotations

import abc
import asyncio
import logging
from typing import Any, Dict, Optional

import aiohttp

from anycaptcha.errors import CaptchaError, CaptchaTimeout

logger = logging.getLogger("anycaptcha.service.base")


class BaseService(abc.ABC):
    """Abstract base class for captcha solving services.

    All services implement createTask/getTaskResult pattern.
    """

    BASE_URL: str = ""
    SERVICE_NAME: str = "base"

    def __init__(self, api_key: str, **kwargs):
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    @abc.abstractmethod
    async def create_task(self, task: Dict[str, Any]) -> str:
        """Create a captcha solving task. Returns task_id."""
        ...

    @abc.abstractmethod
    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task result. Returns None if not ready."""
        ...

    async def solve(
        self,
        task: Dict[str, Any],
        timeout: float = 120.0,
        poll_interval: float = 3.0,
    ) -> Dict[str, Any]:
        """Create task and poll until solved or timeout."""
        task_id = await self.create_task(task)
        logger.debug("%s: Task created: %s", self.SERVICE_NAME, task_id)

        elapsed = 0.0
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            result = await self.get_task_result(task_id)
            if result is not None:
                logger.debug(
                    "%s: Task %s solved in %.1fs",
                    self.SERVICE_NAME, task_id, elapsed,
                )
                return result

        raise CaptchaTimeout(
            f"{self.SERVICE_NAME}: Task {task_id} timed out after {timeout}s"
        )

    async def get_balance(self) -> float:
        """Get account balance. Override in subclasses."""
        return 0.0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
