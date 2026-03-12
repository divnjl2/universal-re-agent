"""
License client — verifies bot license with ishushka.com server.

Real class structure from memory dump:
  common.license.LicenseInfo  (dataclass)
  common.license.TokenPayload (dataclass)
  LicenseClient.__init__
  LicenseClient._build_payload
  LicenseClient._collect_hwid
  LicenseClient._decode_and_verify
  LicenseClient._ensure_token
  LicenseClient._fetch_challenge
  LicenseClient._get_auth
  LicenseClient._get_server_url
  LicenseClient._hwid
  LicenseClient._is_token_valid
  LicenseClient._refresh_token
  LicenseClient._sign
  LicenseClient.close
  LicenseClient.from_license_file
  LicenseClient.get_license
  LicenseClient.require_license
  LicenseInfo.allows
  LicenseInfo.cancel_date_str

Real paths from memory:
  C:\\Tools\\Farm\\KYCBot\\license.json
  /license/challenge
  /license/check

Real UI strings:
  "Лицензия бота истекла. Бот остановлен."
  "Сервер лицензий временно недоступен, попытка будет повторена"
  "Все попытки проверки лицензии исчерпаны"
  "Ошибка при проверке лицензии"
  "⚠️ Лицензия истекает завтра (<date>)"
  "❌ Лицензия истекает сегодня в 23:59 (<date>)"
  "❌ Лицензия истекла. Бот остановлен."
  "❌ Лицензия недействительна. Бот остановлен."
  "🔑 Лицензия недоступна"
  "🔑⏱️ Лицензия истекла"
  "🔑💻 Превышено максимальное количество устройств"
  "⚠️  Другая копия программы уже запущена!"
  "Failed to get HWID"
  "Failed to read HWID attribute"
  "Invalid license"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import platform
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

# License file location
LICENSE_FILE_PATH = Path("license.json")


@dataclass
class TokenPayload:
    """Decoded JWT/license token payload."""
    hwid: str = ""
    cancel_date: Optional[str] = None  # ISO format
    modules: list[str] = field(default_factory=list)
    max_devices: int = 1
    exp: Optional[int] = None  # Unix timestamp


@dataclass
class LicenseInfo:
    """
    Parsed and validated license information.

    Real properties from memory: allows(), cancel_date_str
    """
    valid: bool = False
    hwid: str = ""
    cancel_date: Optional[datetime] = None
    modules: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def allows(self, module_name: str) -> bool:
        """Check if a module is allowed by this license."""
        if not self.valid:
            return False
        if "*" in self.modules:
            return True
        return module_name in self.modules

    @property
    def cancel_date_str(self) -> str:
        """Human-readable cancel date."""
        if self.cancel_date:
            return self.cancel_date.strftime("%d.%m.%Y %H:%M")
        return "бессрочная"


class LicenseClient:
    """
    License verification client.

    Communicates with the license server (ishushka.com) to validate
    the bot's license using HWID binding and challenge-response auth.

    Real methods recovered from memory dump.
    """

    def __init__(
        self,
        license_path: Path | str = LICENSE_FILE_PATH,
        server_urls: list[str] | None = None,
    ) -> None:
        self._license_path = Path(license_path)
        self._server_urls = server_urls or [
            "https://api.ishushka.com",
        ]
        self._token: Optional[str] = None
        self._token_expires: float = 0
        self._hwid: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._license_data: dict = {}

    @classmethod
    def from_license_file(cls, path: str | Path = LICENSE_FILE_PATH) -> LicenseClient:
        """Create a LicenseClient by loading license.json."""
        client = cls(license_path=path)
        if Path(path).exists():
            with open(path, "r", encoding="utf-8") as f:
                client._license_data = json.load(f)
        return client

    def _collect_hwid(self) -> str:
        """
        Collect hardware identifier for this machine.

        Real methods: _collect_hwid, _hwid (property), "Failed to get HWID"
        """
        if self._hwid:
            return self._hwid

        try:
            mac = uuid.getnode()
            system_info = f"{platform.system()}-{platform.machine()}-{platform.processor()}"
            raw = f"{mac}:{system_info}"
            self._hwid = hashlib.sha256(raw.encode()).hexdigest()[:32]
        except Exception:
            logger.error("Failed to get HWID")
            self._hwid = "unknown"

        return self._hwid

    def _get_server_url(self) -> str:
        """Get the first available license server URL."""
        return self._server_urls[0]

    def _sign(self, payload: str) -> str:
        """Sign a payload with the license key."""
        key = self._license_data.get("key", "")
        return hmac.new(
            key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _build_payload(self) -> dict:
        """Build the license check request payload."""
        hwid = self._collect_hwid()
        return {
            "hwid": hwid,
            "key": self._license_data.get("key", ""),
            "product": "kyc_bot",
            "version": "1.0",
        }

    def _is_token_valid(self) -> bool:
        """Check if the cached auth token is still valid."""
        if not self._token:
            return False
        return time.time() < self._token_expires

    async def _get_auth(self) -> dict[str, str]:
        """Get authentication headers, refreshing token if needed."""
        if not self._is_token_valid():
            await self._refresh_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def _ensure_token(self) -> None:
        """Ensure we have a valid auth token."""
        if not self._is_token_valid():
            await self._refresh_token()

    async def _fetch_challenge(self) -> Optional[str]:
        """
        Fetch a challenge from the license server.

        Real endpoint: /license/challenge
        """
        url = f"{self._get_server_url()}/license/challenge"
        try:
            session = await self._get_session()
            async with session.post(url, json=self._build_payload()) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("challenge")
        except Exception as e:
            logger.error("Failed to fetch challenge: %s", e)
        return None

    async def _refresh_token(self) -> None:
        """Refresh the auth token via challenge-response."""
        challenge = await self._fetch_challenge()
        if challenge:
            signed = self._sign(challenge)
            url = f"{self._get_server_url()}/license/check"
            try:
                session = await self._get_session()
                payload = {
                    **self._build_payload(),
                    "challenge": challenge,
                    "response": signed,
                }
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._token = data.get("token")
                        self._token_expires = time.time() + data.get("expires_in", 3600)
            except Exception as e:
                logger.error("Failed to refresh token: %s", e)

    def _decode_and_verify(self, token_data: dict) -> LicenseInfo:
        """Decode and verify the license response."""
        hwid = self._collect_hwid()

        licensed_hwid = token_data.get("hwid", "")
        if licensed_hwid and licensed_hwid != hwid:
            return LicenseInfo(
                valid=False,
                hwid=hwid,
                error=f"HWID mismatch: expected {licensed_hwid}, got {hwid}",
            )

        cancel_date_str = token_data.get("cancel_date") or token_data.get("cancele_date")
        cancel_date = None
        if cancel_date_str:
            try:
                cancel_date = datetime.fromisoformat(cancel_date_str)
            except (ValueError, TypeError):
                pass

        if cancel_date and datetime.utcnow() > cancel_date:
            return LicenseInfo(
                valid=False,
                hwid=hwid,
                cancel_date=cancel_date,
                error="License expired",
            )

        modules = token_data.get("modules", ["*"])

        return LicenseInfo(
            valid=True,
            hwid=hwid,
            cancel_date=cancel_date,
            modules=modules,
        )

    async def get_license(self) -> LicenseInfo:
        """
        Get and validate the current license.

        Real UI strings on failure:
          "Сервер лицензий временно недоступен, попытка будет повторена"
          "Все попытки проверки лицензии исчерпаны"
        """
        # Try from local license file first
        if self._license_data:
            info = self._decode_and_verify(self._license_data)
            if info.valid:
                return info

        # Try from server
        max_retries = 3
        for attempt in range(max_retries):
            try:
                await self._ensure_token()
                url = f"{self._get_server_url()}/license/check"
                session = await self._get_session()
                headers = await self._get_auth()

                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._decode_and_verify(data)

                logger.warning(
                    "Сервер лицензий временно недоступен, попытка будет повторена (%d/%d)",
                    attempt + 1, max_retries,
                )
            except Exception as e:
                logger.error("Ошибка при проверке лицензии: %s", e)

        logger.error("Все попытки проверки лицензии исчерпаны")
        return LicenseInfo(valid=False, error="All license check attempts exhausted")

    async def require_license(self) -> LicenseInfo:
        """
        Get license, raise if invalid.

        Used at bot startup. Stops the bot if license is invalid.
        """
        info = await self.get_license()
        if not info.valid:
            logger.critical("❌ Лицензия недействительна. Бот остановлен. Error: %s", info.error)
        return info

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
