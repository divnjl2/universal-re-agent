"""
IMAP email client — retrieves verification codes from email providers.

Supports: Gmail, Mail.ru, Outlook (OAuth2), Rambler, firstmail, iCloud.
Extracts Bybit verification codes from email subjects and bodies.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import logging
import re
import ssl
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("bybit_manager.imap")

# Known IMAP servers by email domain
IMAP_SERVERS: Dict[str, Tuple[str, int]] = {
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),
    "mail.ru": ("imap.mail.ru", 993),
    "inbox.ru": ("imap.mail.ru", 993),
    "list.ru": ("imap.mail.ru", 993),
    "bk.ru": ("imap.mail.ru", 993),
    "outlook.com": ("outlook.office365.com", 993),
    "hotmail.com": ("outlook.office365.com", 993),
    "live.com": ("outlook.office365.com", 993),
    "rambler.ru": ("imap.rambler.ru", 993),
    "firstmail.ltd": ("imap.firstmail.ltd", 993),
    "icloud.com": ("imap.mail.me.com", 993),
}

# Bybit sender addresses
BYBIT_SENDERS = [
    "no-reply@bybit.com",
    "do-not-reply@bybit.com",
    "noreply@bybit.com",
]

# Regex patterns to extract 6-digit verification code (ordered by specificity)
# Bybit typically sends codes like "Your verification code is: 123456"
# or "verification code is 123456" or just a 6-digit code in subject
CODE_PATTERNS = [
    re.compile(r"(?:verification|verify|code|confirm)[^0-9]{0,30}(\d{6})", re.IGNORECASE),
    re.compile(r"(\d{6})[^0-9]{0,30}(?:verification|verify|code|confirm)", re.IGNORECASE),
    re.compile(r"\b(\d{6})\b"),  # fallback: any standalone 6-digit number
]


def _get_imap_server(email_address: str) -> Tuple[str, int]:
    """Determine IMAP server from email address domain."""
    domain = email_address.split("@")[-1].lower()
    if domain in IMAP_SERVERS:
        return IMAP_SERVERS[domain]
    # Fall back to generic imap.domain
    return (f"imap.{domain}", 993)


def _decode_header_value(value: str) -> str:
    """Decode email header value (handles encoded words)."""
    parts = decode_header(value)
    result = []
    for data, charset in parts:
        if isinstance(data, bytes):
            result.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(str(data))
    return "".join(result)


def _extract_code_from_text(text: str) -> Optional[str]:
    """Extract 6-digit Bybit verification code from text.

    Tries specific patterns first (e.g. 'verification code is 123456'),
    falls back to any standalone 6-digit number.
    """
    for pattern in CODE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


class ImapClient:
    """Async IMAP client for retrieving Bybit verification codes."""

    def __init__(
        self,
        email_address: str,
        password: str,
        imap_address: Optional[str] = None,
        proxy: Optional[str] = None,
        client_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ):
        self.email_address = email_address
        self.password = password
        self.imap_address = imap_address
        self.proxy = proxy
        self.client_id = client_id
        self.refresh_token = refresh_token
        self._connection: Optional[imaplib.IMAP4_SSL] = None

    async def connect(self) -> None:
        """Connect to IMAP server."""
        if self.imap_address:
            host, port = self.imap_address, 993
            if ":" in self.imap_address:
                host, port_str = self.imap_address.rsplit(":", 1)
                port = int(port_str)
        else:
            host, port = _get_imap_server(self.email_address)

        logger.debug("Connecting to IMAP %s:%d for %s", host, port, self.email_address)

        loop = asyncio.get_event_loop()
        ctx = ssl.create_default_context()

        self._connection = await loop.run_in_executor(
            None,
            lambda: imaplib.IMAP4_SSL(host, port, ssl_context=ctx),
        )

        if self.client_id and self.refresh_token:
            # OAuth2 authentication (Outlook)
            await self._oauth2_login()
        else:
            await loop.run_in_executor(
                None,
                lambda: self._connection.login(self.email_address, self.password),
            )

        logger.debug("IMAP login successful for %s", self.email_address)

    async def _oauth2_login(self) -> None:
        """Authenticate via OAuth2 (for Outlook/Microsoft)."""
        # Build XOAUTH2 string
        auth_string = (
            f"user={self.email_address}\x01"
            f"auth=Bearer {self.refresh_token}\x01\x01"
        )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self._connection.authenticate(
                "XOAUTH2",
                lambda _: auth_string.encode(),
            ),
        )

    async def disconnect(self) -> None:
        """Disconnect from IMAP server."""
        if self._connection:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._connection.logout)
            except Exception:
                pass
            self._connection = None

    async def get_verification_code(
        self,
        email: str = "",
        subject_filter: str = "Bybit",
        max_age_seconds: int = 300,
    ) -> Optional[str]:
        """Single-pass search for a Bybit verification code in recent emails.

        This method does NOT poll — the caller (PrivateClient._wait_for_email_code)
        handles the retry/polling loop.

        Args:
            email: Email address (unused, kept for interface compatibility;
                   the connection is already bound to self.email_address).
            subject_filter: Filter string that must appear in the email subject.
            max_age_seconds: Max age of email to consider (default 5 min).

        Returns:
            6-digit code string or None.
        """
        code = await self._search_for_code(subject_filter, max_age_seconds)
        if code:
            logger.info("Found Bybit code for %s", self.email_address)
        return code

    async def get_bybit_code(
        self,
        subject_contains: Optional[str] = None,
        max_age_seconds: int = 300,
        max_attempts: int = 30,
        attempt_delay: float = 5.0,
    ) -> Optional[str]:
        """Poll for a Bybit verification code in recent emails.

        Args:
            subject_contains: Optional filter for email subject.
            max_age_seconds: Max age of email to consider (default 5 min).
            max_attempts: Number of polling attempts.
            attempt_delay: Seconds between attempts.

        Returns:
            6-digit code string or None.
        """
        for attempt in range(max_attempts):
            code = await self._search_for_code(subject_contains, max_age_seconds)
            if code:
                logger.info(
                    "Found Bybit code for %s on attempt %d",
                    self.email_address, attempt + 1,
                )
                return code

            if attempt < max_attempts - 1:
                await asyncio.sleep(attempt_delay)

        logger.warning(
            "No Bybit code found for %s after %d attempts",
            self.email_address, max_attempts,
        )
        return None

    async def _search_for_code(
        self,
        subject_contains: Optional[str],
        max_age_seconds: int,
    ) -> Optional[str]:
        """Search recent emails for a Bybit verification code."""
        if not self._connection:
            await self.connect()

        loop = asyncio.get_event_loop()

        # Select INBOX
        await loop.run_in_executor(
            None,
            lambda: self._connection.select("INBOX"),
        )

        # Search for recent emails from Bybit
        since_date = (
            datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        ).strftime("%d-%b-%Y")

        _, msg_ids = await loop.run_in_executor(
            None,
            lambda: self._connection.search(None, f'(SINCE "{since_date}")'),
        )

        if not msg_ids or not msg_ids[0]:
            return None

        ids = msg_ids[0].split()
        # Check most recent first
        for msg_id in reversed(ids[-20:]):
            code = await self._check_message(msg_id, subject_contains)
            if code:
                return code

        return None

    async def _check_message(
        self,
        msg_id: bytes,
        subject_contains: Optional[str],
    ) -> Optional[str]:
        """Check a single email message for a Bybit code."""
        loop = asyncio.get_event_loop()

        _, data = await loop.run_in_executor(
            None,
            lambda: self._connection.fetch(msg_id, "(RFC822)"),
        )

        if not data or not data[0]:
            return None

        raw_email = data[0][1]
        if isinstance(raw_email, bytes):
            msg = email.message_from_bytes(raw_email)
        else:
            return None

        # Check sender
        from_addr = msg.get("From", "").lower()
        is_bybit = any(sender in from_addr for sender in BYBIT_SENDERS)
        if not is_bybit:
            return None

        # Check subject filter
        subject = _decode_header_value(msg.get("Subject", ""))
        if subject_contains and subject_contains.lower() not in subject.lower():
            return None

        # Extract code from subject
        code = _extract_code_from_text(subject)
        if code:
            return code

        # Extract code from body
        body = self._get_email_body(msg)
        if body:
            code = _extract_code_from_text(body)
            if code:
                return code

        return None

    @staticmethod
    def _get_email_body(msg: email.message.Message) -> str:
        """Extract text body from email message."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()
