"""
Anycaptcha solver — unified async captcha solving across multiple services.

Supports: capmonster, anti-captcha, capsolver, 2captcha, rucaptcha,
azcaptcha, captcha.guru (sctg), DeathByCaptcha.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Type

from .captcha.base import BaseCaptcha, BaseCaptchaSolution
from .captcha.recaptcha_v2 import RecaptchaV2, RecaptchaV2Solution
from .captcha.geetest import GeeTest, GeeTestSolution
from .captcha.geetest_v4 import GeeTestV4, GeeTestV4Solution
from .errors import AnyCaptchaException, CaptchaError, CaptchaTimeout

logger = logging.getLogger("anycaptcha.solver")


class CaptchaSolver:
    """
    Async captcha solver with service fallback.

    Usage:
        solver = CaptchaSolver(services=[
            {"service": "capmonster", "api_key": "..."},
            {"service": "2captcha", "api_key": "..."},
        ])
        task = RecaptchaV2(site_key="...", page_url="...")
        result = await solver.solve(task)
    """

    def __init__(
        self,
        services: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 180,
        poll_interval: int = 5,
    ):
        self.services = services or []
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._service_clients: Dict[str, Any] = {}

    def _get_service_client(self, service_config: Dict[str, Any]) -> Any:
        """Get or create a service client for the given config."""
        service_name = service_config.get("service", "capmonster")
        api_key = service_config.get("api_key", "")
        cache_key = f"{service_name}:{api_key}"

        if cache_key not in self._service_clients:
            client = self._create_service_client(service_name, api_key)
            self._service_clients[cache_key] = client

        return self._service_clients[cache_key]

    def _create_service_client(self, service_name: str, api_key: str) -> Any:
        """Create a captcha service client."""
        from .service.capmonster import CapMonsterService
        from .service.twocaptcha import TwoCaptchaService
        from .service.anti_captcha import AntiCaptchaService
        from .service.capsolver import CapsolverService
        from .service.rucaptcha import RuCaptchaService
        from .service.azcaptcha import AzCaptchaService

        service_map = {
            "capmonster": CapMonsterService,
            "anti_captcha": AntiCaptchaService,
            "2captcha": TwoCaptchaService,
            "rucaptcha": RuCaptchaService,
            "capsolver": CapsolverService,
            "azcaptcha": AzCaptchaService,
        }

        cls = service_map.get(service_name)
        if cls is None:
            raise AnyCaptchaException(f"Unknown captcha service: {service_name}")

        return cls(api_key=api_key)

    async def solve(
        self,
        task: BaseCaptcha,
        timeout: Optional[int] = None,
    ) -> BaseCaptchaSolution:
        """
        Solve a captcha task using configured services (with fallback).

        Tries each service in order until one succeeds.
        """
        timeout = timeout or self.timeout
        last_error: Optional[Exception] = None

        for service_config in self.services:
            if not service_config.get("enabled", True):
                continue

            try:
                client = self._get_service_client(service_config)
                result = await client.solve(task, timeout=timeout, poll_interval=self.poll_interval)
                if result.ok:
                    logger.info(
                        "Captcha solved via %s (task_id=%s)",
                        service_config.get("service"), result.task_id,
                    )
                    return result
                last_error = CaptchaError(f"Solution not OK: {result.error}")
            except Exception as e:
                last_error = e
                logger.warning(
                    "Captcha service %s failed: %s",
                    service_config.get("service"), e,
                )
                continue

        raise last_error or AnyCaptchaException("No captcha services available")

    async def close(self) -> None:
        """Close all service clients."""
        for client in self._service_clients.values():
            if hasattr(client, "close"):
                await client.close()
        self._service_clients.clear()
