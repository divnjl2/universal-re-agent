"""
better_proxy.proxy — Proxy class for parsing and formatting proxy strings.

Reconstructed from:
- Traffic analysis: proxies sent as "user:pass@host:port" strings
- aiohttp usage: expects "http://user:pass@host:port" (full URL with scheme)
- CapMonster/anycaptcha usage: expects "user:pass@host:port" (no scheme)
- Config credential_pattern: "{user}_country-{cc}_session-{session}_lifetime-168h:{pass}"
- Providers: iProyal (geo.iproyal.com:11250), DataImpulse (gw.dataimpulse.com:823),
             NodeMaven (gate.nodemaven.com:8080)

The original better_proxy package (PyPI) uses this exact interface.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import quote, unquote


class Proxy:
    """Residential/datacenter proxy with credentials.

    Supports multiple input formats:
    - protocol://user:pass@host:port
    - user:pass@host:port
    - host:port:user:pass
    - host:port

    Output formats:
    - __str__()         -> "http://user:pass@host:port"  (aiohttp-ready)
    - as_url            -> "http://user:pass@host:port"  (same, explicit property)
    - as_proxies_dict   -> {"http": "http://...", "https": "http://..."}
    - login_password    -> "user:pass@host:port" (CapMonster / bare format)
    """

    def __init__(
        self,
        host: str,
        port: int,
        login: Optional[str] = None,
        password: Optional[str] = None,
        protocol: str = "http",
    ):
        self.host = host
        self.port = int(port)
        self.login = login or ""
        self.password = password or ""
        self.protocol = protocol.lower()

    # ================================================================
    # Parsing
    # ================================================================

    @classmethod
    def from_string(cls, proxy_str: str) -> "Proxy":
        """Parse a proxy string in any common format.

        Accepted formats:
            protocol://login:password@host:port
            login:password@host:port
            host:port:login:password
            host:port
        """
        proxy_str = proxy_str.strip()
        protocol = "http"

        # Strip protocol prefix
        if "://" in proxy_str:
            protocol, proxy_str = proxy_str.split("://", 1)
            protocol = protocol.lower()

        # Format: login:password@host:port
        if "@" in proxy_str:
            auth, hostport = proxy_str.rsplit("@", 1)
            parts = auth.split(":", 1)
            login = unquote(parts[0])
            password = unquote(parts[1]) if len(parts) > 1 else ""
            hp = hostport.split(":")
            host = hp[0]
            port = int(hp[1]) if len(hp) > 1 else 8080
        else:
            parts = proxy_str.split(":")
            if len(parts) == 2:
                # host:port
                host, port_str = parts
                port = int(port_str)
                login = ""
                password = ""
            elif len(parts) == 4:
                # host:port:login:password
                host = parts[0]
                port = int(parts[1])
                login = parts[2]
                password = parts[3]
            elif len(parts) > 4:
                # host:port:login_with_colons:password
                # Credential patterns like "user_country-DZ_session-abc:pass"
                # contain no extra colons, but be safe: host:port:rest
                host = parts[0]
                port = int(parts[1])
                # Remaining parts are login:password — split on last colon
                rest = ":".join(parts[2:])
                # The credential_pattern has exactly one colon separating
                # login-part and password, so rsplit on last colon
                if ":" in rest:
                    login, password = rest.rsplit(":", 1)
                else:
                    login = rest
                    password = ""
            else:
                raise ValueError(f"Cannot parse proxy string: {proxy_str!r}")

        return cls(
            host=host,
            port=port,
            login=login,
            password=password,
            protocol=protocol,
        )

    # Alias used by some callers
    parse = from_string

    # ================================================================
    # Formatting
    # ================================================================

    def __str__(self) -> str:
        """Return full proxy URL suitable for aiohttp: http://user:pass@host:port"""
        return self.as_url

    def __repr__(self) -> str:
        masked_pw = "***" if self.password else ""
        return (
            f"Proxy(host={self.host!r}, port={self.port}, "
            f"login={self.login!r}, password={masked_pw!r}, "
            f"protocol={self.protocol!r})"
        )

    @property
    def as_url(self) -> str:
        """Full proxy URL with protocol — for aiohttp, requests, etc.

        Returns: "http://login:password@host:port" or "http://host:port"
        """
        if self.login:
            # URL-encode credentials in case they contain special chars
            encoded_login = quote(self.login, safe="")
            encoded_pass = quote(self.password, safe="")
            return f"{self.protocol}://{encoded_login}:{encoded_pass}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def login_password(self) -> str:
        """Bare proxy string without protocol — for CapMonster, 2captcha, etc.

        Returns: "login:password@host:port" or "host:port"
        """
        if self.login:
            return f"{self.login}:{self.password}@{self.host}:{self.port}"
        return f"{self.host}:{self.port}"

    @property
    def as_proxies_dict(self) -> dict:
        """Dict format for requests library: {"http": url, "https": url}."""
        url = self.as_url
        return {"http": url, "https": url}

    # ================================================================
    # Equality and hashing
    # ================================================================

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Proxy):
            return NotImplemented
        return (
            self.host == other.host
            and self.port == other.port
            and self.login == other.login
            and self.password == other.password
        )

    def __hash__(self) -> int:
        return hash((self.host, self.port, self.login, self.password))

    # ================================================================
    # Convenience factory for provider credential patterns
    # ================================================================

    @classmethod
    def from_provider(
        cls,
        provider_config: dict,
        user: str,
        password: str,
        country_code: str = "DZ",
        session_id: Optional[str] = None,
    ) -> "Proxy":
        """Build a Proxy from a PROXY_PROVIDERS config entry.

        Args:
            provider_config: Dict with host, port, credential_pattern keys.
            user: Provider account username.
            password: Provider account password.
            country_code: 2-letter ISO country code (default "DZ" for Algeria).
            session_id: Sticky session ID (generated if not provided).

        Returns:
            Proxy instance ready for use.
        """
        import uuid as _uuid

        host = provider_config["host"]
        port = provider_config["port"]
        pattern = provider_config.get(
            "credential_pattern",
            "{user}_country-{cc}_session-{session}_lifetime-168h:{pass}",
        )

        if session_id is None:
            session_id = _uuid.uuid4().hex[:16]

        # Pattern produces "login_part:password_part"
        credential = pattern.format(
            user=user,
            cc=country_code,
            session=session_id,
            **{"pass": password},
        )

        # Split on last colon to get login and password parts
        if ":" in credential:
            login, pwd = credential.rsplit(":", 1)
        else:
            login = credential
            pwd = ""

        return cls(host=host, port=port, login=login, password=pwd, protocol="http")
