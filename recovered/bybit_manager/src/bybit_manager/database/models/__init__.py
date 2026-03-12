"""
SQLAlchemy ORM models — all 16 database tables.
Import all models here so Base.metadata has them registered.
"""

from .base import Base
from .email import Email
from .account import BybitAccount
from .finance_account import FinanceAccount, FinanceAccountType
from .deposit_address import DepositAddress
from .deposit_history import DepositHistory
from .withdraw_address import WithdrawAddress
from .withdraw_history import WithdrawHistory
from .award import (
    Award, AwardStatus, AwardUsingStatus, AwardType,
    AwardAmountUnit, BusinessNo, AutoClaimType,
    ProductLine, SubProductLine,
)
from .airdrophunt import AirdropHunt
from .tokensplash import TokenSplash
from .puzzlehunt import PuzzleHunt
from .ido import IDO
from .web3_wallet import Web3Wallet, WalletType
from .web3_chain import Web3Chain, Web3ChainType
from .web3_token import Web3Token

__all__ = [
    "Base",
    "Email",
    "BybitAccount",
    "FinanceAccount",
    "FinanceAccountType",
    "DepositAddress",
    "DepositHistory",
    "WithdrawAddress",
    "WithdrawHistory",
    "Award",
    "AwardStatus",
    "AwardUsingStatus",
    "AwardType",
    "AwardAmountUnit",
    "BusinessNo",
    "AutoClaimType",
    "ProductLine",
    "SubProductLine",
    "AirdropHunt",
    "TokenSplash",
    "PuzzleHunt",
    "IDO",
    "Web3Wallet",
    "WalletType",
    "Web3Chain",
    "Web3ChainType",
    "Web3Token",
]
