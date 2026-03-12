"""
Email client manager — manages IMAP connections per email provider.

Thin wrapper around ImapClient for the manager layer.
Supports: Gmail, Mail.ru, Outlook (OAuth2), Rambler, firstmail, iCloud.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from bybit_manager.imap import ImapClient

logger = logging.getLogger("bybit_manager.email_client")


class EmailClientManager:
    """Manages email connections for verification code retrieval."""

    def __init__(self, email_services: Dict[str, Dict[str, Any]]):
        """
        Args:
            email_services: Config section for email services.
                E.g. {"gmail": {"enabled": true}, "outlook": {"client_id": "..."}}
        """
        self.email_services = email_services
        self._clients: Dict[str, ImapClient] = {}

    def create_client(
        self,
        email_address: str,
        password: str,
        imap_address: Optional[str] = None,
        proxy: Optional[str] = None,
        client_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> ImapClient:
        """Create an IMAP client for the given email address."""
        domain = email_address.split("@")[-1].lower()

        # Check if we have OAuth2 config for this provider
        if domain in ("outlook.com", "hotmail.com", "live.com"):
            outlook_config = self.email_services.get("outlook", {})
            if not client_id:
                client_id = outlook_config.get("client_id")
            # refresh_token is per-email, not global

        client = ImapClient(
            email_address=email_address,
            password=password,
            imap_address=imap_address,
            proxy=proxy,
            client_id=client_id,
            refresh_token=refresh_token,
        )

        return client

    async def get_bybit_code(
        self,
        email_address: str,
        password: str,
        imap_address: Optional[str] = None,
        proxy: Optional[str] = None,
        client_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
        subject_contains: Optional[str] = None,
        max_age_seconds: int = 300,
        max_attempts: int = 30,
    ) -> Optional[str]:
        """Convenience method: create client, connect, retrieve code, disconnect."""
        client = self.create_client(
            email_address=email_address,
            password=password,
            imap_address=imap_address,
            proxy=proxy,
            client_id=client_id,
            refresh_token=refresh_token,
        )
        try:
            async with client:
                return await client.get_bybit_code(
                    subject_contains=subject_contains,
                    max_age_seconds=max_age_seconds,
                    max_attempts=max_attempts,
                )
        except Exception as e:
            logger.error(
                "Failed to get Bybit code for %s: %s",
                email_address, e,
            )
            return None
