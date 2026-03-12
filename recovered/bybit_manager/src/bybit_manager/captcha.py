"""
Captcha integration layer — bridges config with anycaptcha solver.

Provides CaptchaManager that creates solvers from config and exposes
a simple solve() interface for the PrivateClient to use.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from anycaptcha.solver import CaptchaSolver
from anycaptcha.captcha.recaptcha_v2 import RecaptchaV2
from anycaptcha.captcha.geetest import GeeTest
from anycaptcha.captcha.geetest_v4 import GeeTestV4

logger = logging.getLogger("bybit_manager.captcha")


class CaptchaManager:
    """Manages captcha solving across multiple services with fallback."""

    def __init__(self, services_config: List[Dict[str, Any]]):
        """
        Args:
            services_config: List of service dicts from Config.captcha_services.
                E.g. [{"service": "capmonster", "api_key": "...", "enabled": true, "priority": 0}]
        """
        self.services_config = services_config
        self._solver: Optional[CaptchaSolver] = None
        self._init_solver()

    def _init_solver(self) -> None:
        """Initialize a CaptchaSolver with the configured services list."""
        enabled = [
            svc for svc in self.services_config
            if svc.get("enabled", True)
        ]
        if not enabled:
            logger.warning("No enabled captcha services configured")
            return

        # Sort by priority (lower = higher priority)
        enabled.sort(key=lambda s: s.get("priority", 99))

        self._solver = CaptchaSolver(services=enabled)
        logger.info(
            "CaptchaManager initialized with %d services: %s",
            len(enabled),
            [s.get("service") for s in enabled],
        )

    async def solve_recaptcha_v2(
        self,
        site_key: str,
        page_url: str,
        proxy: Optional[str] = None,
        user_agent: str = "",
    ) -> Optional[str]:
        """Solve reCAPTCHA v2 using available services (with fallback).

        Returns the gRecaptchaResponse token or None.
        """
        if not self._solver:
            logger.error("No captcha solver available")
            return None

        try:
            task = RecaptchaV2(
                site_key=site_key,
                page_url=page_url,
                proxy=proxy,
                user_agent=user_agent,
            )
            result = await self._solver.solve(task)
            if result and result.ok:
                return result.solution.get("gRecaptchaResponse", "")
        except Exception as e:
            logger.error("reCAPTCHA v2 solve failed: %s", e)

        return None

    async def solve_geetest(
        self,
        gt: str,
        challenge: str,
        page_url: str,
        proxy: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Solve GeeTest v3. Returns dict with challenge/validate/seccode."""
        if not self._solver:
            logger.error("No captcha solver available")
            return None

        try:
            task = GeeTest(
                gt=gt,
                challenge=challenge,
                page_url=page_url,
                proxy=proxy,
            )
            result = await self._solver.solve(task)
            if result and result.ok:
                return result.solution
        except Exception as e:
            logger.error("GeeTest solve failed: %s", e)

        return None

    async def solve_geetest_v4(
        self,
        captcha_id: str,
        page_url: str,
        proxy: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Solve GeeTest v4. Returns dict with captcha_id/lot_number/pass_token/gen_time/captcha_output."""
        if not self._solver:
            logger.error("No captcha solver available")
            return None

        try:
            task = GeeTestV4(
                captcha_id=captcha_id,
                page_url=page_url,
                proxy=proxy,
            )
            result = await self._solver.solve(task)
            if result and result.ok:
                return result.solution
        except Exception as e:
            logger.error("GeeTest v4 solve failed: %s", e)

        return None

    async def close(self) -> None:
        """Close underlying solver and all service clients."""
        if self._solver:
            await self._solver.close()
