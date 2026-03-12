"""
Country models — country data and trading permission structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Country:
    """Country info from Bybit."""
    code: str = ""  # ISO 3166-1 alpha-2
    name: str = ""
    phone_code: str = ""
    supported: bool = True
    kyc_required: bool = False
    restricted: bool = False


@dataclass
class CountryPermission:
    """Trading permissions for a country."""
    country_code: str = ""
    spot_allowed: bool = True
    contract_allowed: bool = True
    margin_allowed: bool = True
    fiat_allowed: bool = False
    p2p_allowed: bool = False
    kyc_level_required: int = 0
    withdraw_allowed: bool = True
    deposit_allowed: bool = True
