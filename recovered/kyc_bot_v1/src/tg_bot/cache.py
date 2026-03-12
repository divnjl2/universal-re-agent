"""
Simple in-memory cache for frequently accessed data.

From memory: tg_bot.cache
"""
from __future__ import annotations

import time
from typing import Any, Optional


class SimpleCache:
    """TTL-based in-memory cache."""

    def __init__(self, default_ttl: float = 60.0) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """Get value if not expired."""
        if key in self._store:
            value, expires_at = self._store[key]
            if time.monotonic() < expires_at:
                return value
            del self._store[key]
        return None

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value with TTL."""
        ttl = ttl or self._default_ttl
        self._store[key] = (value, time.monotonic() + ttl)

    def delete(self, key: str) -> None:
        """Delete a key."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Clear all entries."""
        self._store.clear()


# Singleton cache instance
cache = SimpleCache(default_ttl=120.0)
