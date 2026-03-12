"""
Captcha integration layer — bridges config with anycaptcha solver.

Provides CaptchaManager that creates solvers from config and exposes
a simple solve() interface for the PrivateClient to use.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from anycaptcha import CaptchaSolver, CaptchaServiceType, CaptchaType

logger = logging.getLogger("bybit_manager.captcha")


# Service name mapping from config to CaptchaServiceType
SERVICE_MAP = {
    "capmonster": CaptchaServiceType.CAPMONSTER,
    "2captcha": CaptchaServiceType.TWOCAPTCHA,
    "rucaptcha": CaptchaServiceType.RUCAPTCHA,
    "anticaptcha": CaptchaServiceType.ANTICAPTCHA,
    "anti-captcha": CaptchaServiceType.ANTICAPTCHA,
    "capsolver": CaptchaServiceType.CAPSOLVER,
    "azcaptcha": CaptchaServiceType.AZCAPTCHA,
    "captcha_guru": CaptchaServiceType.CAPTCHA_GURU,
    "deathbycaptcha": CaptchaServiceType.DEATHBYCAPTCHA,
}


class CaptchaManager:
    """Manages captcha solving across multiple services with fallback."""

    def __init__(self, services_config: List[Dict[str, Any]]):
        """
        Args:
            services_config: List of service dicts from Config.captcha_services.
                E.g. [{"service": "capmonster", "api_key": "...", "enabled": true, "priority": 0}]
        """
        self.services_config = services_config
        self._solvers: List[CaptchaSolver] = []
        self._init_solvers()

    def _init_solvers(self) -> None:
        """Initialize CaptchaSolver instances for each enabled service."""
        for svc in self.services_config:
            if not svc.get("enabled", True):
                continue

            service_name = svc.get("service", "")
            api_key = svc.get("api_key", "")

            service_type = SERVICE_MAP.get(service_name.lower())
            if not service_type:
                logger.warning("Unknown captcha service: %s", service_name)
                continue

            try:
                solver = CaptchaSolver(
                    service_type=service_type,
                    api_key=api_key,
                )
                self._solvers.append(solver)
                logger.info("Captcha solver initialized: %s", service_name)
            except Exception as e:
                logger.error("Failed to init captcha solver %s: %s", service_name, e)

    async def solve_recaptcha_v2(
        self,
        site_key: str,
        page_url: str,
        proxy: Optional[str] = None,
    ) -> Optional[str]:
        """Solve reCAPTCHA v2 using available services (with fallback).

        Returns the solution token or None.
        """
        for solver in self._solvers:
            try:
                result = await solver.solve(
                    captcha_type=CaptchaType.RECAPTCHA_V2,
                    site_key=site_key,
                    page_url=page_url,
                    proxy=proxy,
                )
                if result:
                    return result.solution
            except Exception as e:
                logger.warning("Captcha solve failed with %s: %s", solver, e)
                continue

        logger.error("All captcha services failed for reCAPTCHA v2")
        return None

    async def solve_geetest(
        self,
        gt: str,
        challenge: str,
        page_url: str,
        proxy: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Solve GeeTest v3. Returns dict with challenge/validate/seccode."""
        for solver in self._solvers:
            try:
                result = await solver.solve(
                    captcha_type=CaptchaType.GEETEST,
                    gt=gt,
                    challenge=challenge,
                    page_url=page_url,
                    proxy=proxy,
                )
                if result:
                    return result.solution
            except Exception as e:
                logger.warning("GeeTest solve failed with %s: %s", solver, e)
                continue

        logger.error("All captcha services failed for GeeTest")
        return None

    async def solve_geetest_v4(
        self,
        captcha_id: str,
        page_url: str,
        proxy: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Solve GeeTest v4. Returns dict with captcha_id/lot_number/pass_token/gen_time/captcha_output."""
        for solver in self._solvers:
            try:
                result = await solver.solve(
                    captcha_type=CaptchaType.GEETEST_V4,
                    captcha_id=captcha_id,
                    page_url=page_url,
                    proxy=proxy,
                )
                if result:
                    return result.solution
            except Exception as e:
                logger.warning("GeeTest v4 solve failed with %s: %s", solver, e)
                continue

        logger.error("All captcha services failed for GeeTest v4")
        return None
