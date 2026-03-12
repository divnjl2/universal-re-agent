"""
Manager-level client wrapper — creates and manages PrivateClient instances
per account, handling proxy, cookies, device fingerprint, and email integration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from bybit.client import PrivateClient, BybitDevice, BybitException
from bybit_manager.config import Config
from bybit_manager.imap import ImapClient

logger = logging.getLogger("bybit_manager.client")


class ManagedClient:
    """Wrapper around PrivateClient that adds:
    - Automatic proxy assignment
    - Cookie persistence
    - IMAP email integration for verification codes
    - Captcha service configuration
    - Device fingerprint management
    """

    def __init__(
        self,
        config: Config,
        database_id: int,
        email_address: str,
        password: Optional[str] = None,
        totp_secret: Optional[str] = None,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, Any]] = None,
        device: Optional[BybitDevice] = None,
        imap_address: Optional[str] = None,
        imap_password: Optional[str] = None,
        email_proxy: Optional[str] = None,
        email_client_id: Optional[str] = None,
        email_refresh_token: Optional[str] = None,
        preferred_country_code: Optional[str] = None,
        chrome_major_version: Optional[int] = None,
        os_name: Optional[str] = None,
        screen_width: Optional[int] = None,
        screen_height: Optional[int] = None,
    ):
        self.config = config
        self.database_id = database_id
        self.email_address = email_address
        self.password = password
        self.totp_secret = totp_secret
        self.proxy = proxy
        self.cookies = cookies
        self.preferred_country_code = preferred_country_code

        # Build device fingerprint
        if device:
            self.device = device
        else:
            self.device = BybitDevice(
                chrome_major_version=chrome_major_version,
                os=os_name,
                screen_width=screen_width,
                screen_height=screen_height,
            )

        # IMAP config for email verification codes
        self._imap_address = imap_address
        self._imap_password = imap_password or password
        self._email_proxy = email_proxy
        self._email_client_id = email_client_id
        self._email_refresh_token = email_refresh_token

        # Client instance (created lazily)
        self._client: Optional[PrivateClient] = None

    @property
    def client(self) -> PrivateClient:
        """Get or create the underlying PrivateClient."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> PrivateClient:
        """Create a new PrivateClient instance with all config."""
        # Get captcha services from config
        captcha_services = self.config.captcha_services

        client = PrivateClient(
            proxy=self.proxy,
            device=self.device,
            captcha_services=captcha_services,
            country_code=self.preferred_country_code,
        )

        # Import cookies if available
        if self.cookies:
            client.import_cookies(self.cookies)

        return client

    def get_imap_client(self) -> ImapClient:
        """Create an IMAP client for this account's email."""
        return ImapClient(
            email_address=self.email_address,
            password=self._imap_password or self.password or "",
            imap_address=self._imap_address,
            proxy=self._email_proxy,
            client_id=self._email_client_id,
            refresh_token=self._email_refresh_token,
        )

    async def login(self) -> Dict[str, Any]:
        """Perform full login flow with captcha + 2FA handling."""
        imap_client = self.get_imap_client()
        result = await self.client.login_logic(
            email=self.email_address,
            password=self.password,
            totp_secret=self.totp_secret,
            imap_client=imap_client,
        )
        # Update cookies after login
        self.cookies = self.client.export_cookies()
        return result

    async def withdraw(
        self,
        coin: str,
        chain: str,
        address: str,
        amount: float,
        withdraw_type: int = 0,
    ) -> Dict[str, Any]:
        """Execute withdrawal with automatic risk token handling."""
        imap_client = self.get_imap_client()
        result = await self.client.withdraw_logic(
            coin=coin,
            chain=chain,
            address=address,
            amount=amount,
            withdraw_type=withdraw_type,
            totp_secret=self.totp_secret,
            imap_client=imap_client,
        )
        return result

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client:
            await self._client.close()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


class ClientPool:
    """Pool of ManagedClient instances — reuses clients per database_id."""

    def __init__(self, config: Config):
        self.config = config
        self._clients: Dict[int, ManagedClient] = {}

    def get_or_create(
        self,
        database_id: int,
        email_address: str,
        password: Optional[str] = None,
        totp_secret: Optional[str] = None,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> ManagedClient:
        """Get existing client or create new one."""
        if database_id in self._clients:
            return self._clients[database_id]

        client = ManagedClient(
            config=self.config,
            database_id=database_id,
            email_address=email_address,
            password=password,
            totp_secret=totp_secret,
            proxy=proxy,
            cookies=cookies,
            **kwargs,
        )
        self._clients[database_id] = client
        return client

    async def remove(self, database_id: int) -> None:
        """Close and remove a client from the pool."""
        client = self._clients.pop(database_id, None)
        if client:
            await client.close()

    async def close_all(self) -> None:
        """Close all clients in the pool."""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
