"""
Web3 models — Bybit Web3 wallet and DeFi data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Web3WalletInfo:
    """Web3 wallet info from Bybit."""
    wallet_id: str = ""
    wallet_type: str = ""  # "CLOUD", "PRIVATE_KEY", "MNEMONIC_PHRASE"
    balance_usd: float = 0.0
    chains: List["Web3ChainInfo"] = field(default_factory=list)


@dataclass
class Web3ChainInfo:
    """Chain info within a web3 wallet."""
    chain_id: int = 0
    chain_type: str = ""
    chain_code: str = ""
    address: str = ""
    balance_usd: float = 0.0
    tokens: List["Web3TokenInfo"] = field(default_factory=list)


@dataclass
class Web3TokenInfo:
    """Token info within a chain."""
    contract_address: str = ""
    symbol: str = ""
    balance: float = 0.0
    balance_usd: float = 0.0
    price_usd: float = 0.0


@dataclass
class Web3SwapQuote:
    """Swap quote from Bybit Web3."""
    from_token: str = ""
    to_token: str = ""
    from_amount: float = 0.0
    to_amount: float = 0.0
    price_impact: float = 0.0
    gas_fee_usd: float = 0.0
    route: str = ""


@dataclass
class Web3Transaction:
    """Web3 transaction result."""
    tx_hash: str = ""
    status: str = ""
    chain_id: int = 0
    from_address: str = ""
    to_address: str = ""
    value: float = 0.0
