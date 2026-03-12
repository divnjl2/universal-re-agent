"""
ByFi (Earn) enums.
"""

from __future__ import annotations

from ._base import BybitEnum


class ByFiProductType(BybitEnum):
    FLEXIBLE = "flexible"
    FIXED = "fixed"
    DUAL_CURRENCY = "dual_currency"
    CLOUD_MINING = "cloud_mining"
    DEFI_MINING = "defi_mining"


class ByFiOrderStatus(BybitEnum):
    ACTIVE = "active"
    REDEEMED = "redeemed"
    EXPIRED = "expired"
