"""
Base enum class for Bybit enums.
"""

from __future__ import annotations

import enum


class BybitEnum(str, enum.Enum):
    """Base enum for all Bybit string enumerations."""

    @classmethod
    def from_value(cls, value: str, default=None):
        """Get enum member by value, returning default if not found."""
        try:
            return cls(value)
        except ValueError:
            return default
