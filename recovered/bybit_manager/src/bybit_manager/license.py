"""
License checker — validates license key against ishushka.com server.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import platform
import uuid
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger("bybit_manager.license")


def _get_hwid() -> str:
    """Generate hardware ID from machine characteristics."""
    parts = [
        platform.node(),
        platform.machine(),
        platform.processor(),
        str(uuid.getnode()),  # MAC address
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class LicenseChecker:
    """Validates license key against the license server."""

    def __init__(
        self,
        license_key: str,
        server_url: str = "https://ishushka.com",
    ):
        self.license_key = license_key
        self.server_url = server_url.rstrip("/")
        self.hwid = _get_hwid()
        self._valid: Optional[bool] = None
        self._info: Dict[str, Any] = {}

    async def check(self) -> bool:
        """Check license validity with the server.

        Returns True if license is valid, False otherwise.
        """
        if not self.license_key:
            logger.warning("No license key configured")
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.server_url}/api/v1/license/check",
                    json={
                        "key": self.license_key,
                        "hwid": self.hwid,
                        "product": "bybit_manager",
                        "version": "3.0",
                    },
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._valid = data.get("valid", False)
                        self._info = data
                        if self._valid:
                            logger.info("License valid, expires: %s", data.get("expires_at"))
                        else:
                            logger.warning("License invalid: %s", data.get("message"))
                        return self._valid
                    else:
                        logger.error("License check failed: HTTP %d", resp.status)
                        return False
        except Exception as e:
            logger.error("License check error: %s", e)
            # Fail open for network errors (grace period)
            return True

    @property
    def is_valid(self) -> Optional[bool]:
        """Get last check result (None if never checked)."""
        return self._valid

    @property
    def info(self) -> Dict[str, Any]:
        """Get license info from last check."""
        return self._info

    @property
    def expires_at(self) -> Optional[str]:
        return self._info.get("expires_at")
