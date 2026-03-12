"""
Web3 enums.
"""

from __future__ import annotations

from ._base import BybitEnum


class Web3WalletType(BybitEnum):
    CLOUD = "CLOUD"
    PRIVATE_KEY = "PRIVATE_KEY"
    MNEMONIC_PHRASE = "MNEMONIC_PHRASE"


class Web3ChainType(BybitEnum):
    ALL = "ALL"
    EVM = "EVM"
    SUI = "SUI"
    SOLANA = "SOLANA"
    BTC = "BTC"
    STX = "STX"
    APT = "APT"
    TON = "TON"
    TRON = "TRON"
