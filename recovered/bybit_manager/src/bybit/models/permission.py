"""
Permission models — API key permissions and access control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ApiKeyPermission:
    """API key permission set."""
    read: bool = True
    spot_trade: bool = False
    contract_trade: bool = False
    wallet: bool = False
    exchange: bool = False
    nft: bool = False


@dataclass
class ApiKeyInfo:
    """API key metadata from Bybit."""
    bybit_id: str = ""
    note: str = ""
    key: str = ""
    secret: str = ""
    read_only: bool = True
    permissions: Dict[str, bool] = field(default_factory=dict)
    ipv4_addresses: List[str] = field(default_factory=list)
    created_at: str = ""
