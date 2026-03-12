"""
Award ORM model — reward system with lifecycle tracking.

Table: award (PK: id + uid)
Migration: 2025_05_10 — 556d201c3e5b
Enums: awardstatus, awardusingstatus, awardtype, awardamountunit,
       businessno, autoclaimtype, productline, subproductline
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Enum, Float,
    ForeignKey, Integer, String,
)
from sqlalchemy.orm import relationship

from .base import Base


class AwardStatus(str, enum.Enum):
    AWARDING_STATUS_UNKNOWN = "AWARDING_STATUS_UNKNOWN"
    AWARDING_STATUS_UNCLAIMED = "AWARDING_STATUS_UNCLAIMED"
    AWARDING_STATUS_UNCLAIMED_EXPIRED = "AWARDING_STATUS_UNCLAIMED_EXPIRED"
    AWARDING_STATUS_PENDING = "AWARDING_STATUS_PENDING"
    AWARDING_STATUS_CLAIMED = "AWARDING_STATUS_CLAIMED"


class AwardUsingStatus(str, enum.Enum):
    AWARDING_USING_STATUS_UNKNOWN = "AWARDING_USING_STATUS_UNKNOWN"
    AWARDING_USING_STATUS_IN_USE = "AWARDING_USING_STATUS_IN_USE"
    AWARDING_USING_STATUS_FINISHED = "AWARDING_USING_STATUS_FINISHED"
    AWARDING_USING_STATUS_EXPIRED = "AWARDING_USING_STATUS_EXPIRED"
    AWARDING_USING_STATUS_PENDING = "AWARDING_USING_STATUS_PENDING"
    AWARDING_USING_STATUS_FAILURE = "AWARDING_USING_STATUS_FAILURE"
    AWARDING_USING_STATUS_TRANSFER = "AWARDING_USING_STATUS_TRANSFER"


class AwardType(str, enum.Enum):
    AWARD_TYPE_UNKNOWN = "AWARD_TYPE_UNKNOWN"
    AWARD_TYPE_CASH_CARD = "AWARD_TYPE_CASH_CARD"
    AWARD_TYPE_SERVICE_CASH_CARD = "AWARD_TYPE_SERVICE_CASH_CARD"
    AWARD_TYPE_TRADING_FEE_DISCOUNT_CARD = "AWARD_TYPE_TRADING_FEE_DISCOUNT_CARD"
    AWARD_TYPE_TASK = "AWARD_TYPE_TASK"
    AWARD_TYPE_BYFI_INTEREST = "AWARD_TYPE_BYFI_INTEREST"
    AWARD_TYPE_SPOT_AIR_DROP = "AWARD_TYPE_SPOT_AIR_DROP"
    AWARD_TYPE_VIP_EXPERIENCE_CARD = "AWARD_TYPE_VIP_EXPERIENCE_CARD"
    AWARD_TYPE_VOTES_CARD = "AWARD_TYPE_VOTES_CARD"
    AWARD_TYPE_TRADING_VOUCHER = "AWARD_TYPE_TRADING_VOUCHER"
    AWARD_TYPE_REWARD = "AWARD_TYPE_REWARD"
    AWARD_TYPE_NFT_AIR_DROP = "AWARD_TYPE_NFT_AIR_DROP"
    AWARD_TYPE_LOSS_COVER_VOUCHER = "AWARD_TYPE_LOSS_COVER_VOUCHER"
    AWARD_TYPE_POSITION_AIR_DROP = "AWARD_TYPE_POSITION_AIR_DROP"
    AWARD_TYPE_APR_BOOSTER = "AWARD_TYPE_APR_BOOSTER"
    AWARD_TYPE_NFT_FREE_MINT_CARD = "AWARD_TYPE_NFT_FREE_MINT_CARD"
    AWARD_TYPE_RED_PACK = "AWARD_TYPE_RED_PACK"
    AWARD_TYPE_POINTS = "AWARD_TYPE_POINTS"
    AWARD_TYPE_TRIGGER = "AWARD_TYPE_TRIGGER"
    AWARD_TYPE_OTHERS = "AWARD_TYPE_OTHERS"
    AWARD_TYPE_REWARD_PACKET = "AWARD_TYPE_REWARD_PACKET"
    AWARD_TYPE_CREDIT = "AWARD_TYPE_CREDIT"


class AwardAmountUnit(str, enum.Enum):
    AWARD_AMOUNT_UNIT_USD = "AWARD_AMOUNT_UNIT_USD"
    AWARD_AMOUNT_UNIT_COIN = "AWARD_AMOUNT_UNIT_COIN"


class BusinessNo(str, enum.Enum):
    BUSINESS_NO_UNKNOWN = "BUSINESS_NO_UNKNOWN"
    BUSINESS_NO_VOTE = "BUSINESS_NO_VOTE"
    BUSINESS_NO_PRIZE_DRAW = "BUSINESS_NO_PRIZE_DRAW"
    BUSINESS_NO_BENEFIT_POINTS = "BUSINESS_NO_BENEFIT_POINTS"
    BUSINESS_NO_POINTS = "BUSINESS_NO_POINTS"
    BUSINESS_NO_POINTS_GUESS = "BUSINESS_NO_POINTS_GUESS"
    BUSINESS_NO_POINTS_TICKET = "BUSINESS_NO_POINTS_TICKET"
    BUSINESS_NO_POINTS_MULTI = "BUSINESS_NO_POINTS_MULTI"


class AutoClaimType(str, enum.Enum):
    AUTOCLAIM_UNKNOWN = "AUTOCLAIM_UNKNOWN"
    AUTOCLAIM_YES = "AUTOCLAIM_YES"
    AUTOCLAIM_NO = "AUTOCLAIM_NO"


class ProductLine(str, enum.Enum):
    PRODUCT_LINE_UNKNOWN = "PRODUCT_LINE_UNKNOWN"
    PRODUCT_LINE_CONTRACT = "PRODUCT_LINE_CONTRACT"
    PRODUCT_LINE_SPOT = "PRODUCT_LINE_SPOT"
    PRODUCT_LINE_OPTIONS = "PRODUCT_LINE_OPTIONS"
    PRODUCT_LINE_BYFI = "PRODUCT_LINE_BYFI"
    PRODUCT_LINE_VIP = "PRODUCT_LINE_VIP"
    PRODUCT_LINE_LAUNCH = "PRODUCT_LINE_LAUNCH"
    PRODUCT_LINE_REWARD = "PRODUCT_LINE_REWARD"
    PRODUCT_LINE_FIAT = "PRODUCT_LINE_FIAT"
    PRODUCT_LINE_COPY_TRADING = "PRODUCT_LINE_COPY_TRADING"
    PRODUCT_LINE_NFT = "PRODUCT_LINE_NFT"
    PRODUCT_LINE_BOT = "PRODUCT_LINE_BOT"
    PRODUCT_LINE_BYBIT_CARD = "PRODUCT_LINE_BYBIT_CARD"
    PRODUCT_LINE_P2P = "PRODUCT_LINE_P2P"
    PRODUCT_LINE_EARN = "PRODUCT_LINE_EARN"
    PRODUCT_LINE_BYBIT_PAY = "PRODUCT_LINE_BYBIT_PAY"


class SubProductLine(str, enum.Enum):
    SUB_PRODUCT_LINE_UNKNOWN = "SUB_PRODUCT_LINE_UNKNOWN"
    SUB_PRODUCT_LINE_CONTRACT_DEFAULT = "SUB_PRODUCT_LINE_CONTRACT_DEFAULT"
    SUB_PRODUCT_LINE_CONTRACT_INVERSE = "SUB_PRODUCT_LINE_CONTRACT_INVERSE"
    SUB_PRODUCT_LINE_CONTRACT_LINEAR = "SUB_PRODUCT_LINE_CONTRACT_LINEAR"
    SUB_PRODUCT_LINE_CONTRACT_COMMON = "SUB_PRODUCT_LINE_CONTRACT_COMMON"
    SUB_PRODUCT_LINE_SPOT_DEFAULT = "SUB_PRODUCT_LINE_SPOT_DEFAULT"
    SUB_PRODUCT_LINE_SPOT_TRADING = "SUB_PRODUCT_LINE_SPOT_TRADING"
    SUB_PRODUCT_LINE_OPTIONS_DEFAULT = "SUB_PRODUCT_LINE_OPTIONS_DEFAULT"
    SUB_PRODUCT_LINE_OPTIONS_COMMON = "SUB_PRODUCT_LINE_OPTIONS_COMMON"
    SUB_PRODUCT_LINE_OPTIONS_FUTURE = "SUB_PRODUCT_LINE_OPTIONS_FUTURE"
    SUB_PRODUCT_LINE_OPTIONS_OPTION = "SUB_PRODUCT_LINE_OPTIONS_OPTION"
    SUB_PRODUCT_LINE_BYFI_EARN = "SUB_PRODUCT_LINE_BYFI_EARN"
    SUB_PRODUCT_LINE_CLOUD_MINING = "SUB_PRODUCT_LINE_CLOUD_MINING"
    SUB_PRODUCT_LINE_DEFI_MINING = "SUB_PRODUCT_LINE_DEFI_MINING"
    SUB_PRODUCT_LINE_DUAL_CURRENCY = "SUB_PRODUCT_LINE_DUAL_CURRENCY"
    SUB_PRODUCT_LINE_LAUNCH_POOL = "SUB_PRODUCT_LINE_LAUNCH_POOL"
    SUB_PRODUCT_LINE_VIP_DEFAULT = "SUB_PRODUCT_LINE_VIP_DEFAULT"
    SUB_PRODUCT_LINE_BY_VOTES = "SUB_PRODUCT_LINE_BY_VOTES"
    SUB_PRODUCT_LINE_REWARD_DEFAULT = "SUB_PRODUCT_LINE_REWARD_DEFAULT"
    SUB_PRODUCT_LINE_FIAT_ALL = "SUB_PRODUCT_LINE_FIAT_ALL"
    SUB_PRODUCT_LINE_FIAT_CREDIT_CARD_PAYMENT = "SUB_PRODUCT_LINE_FIAT_CREDIT_CARD_PAYMENT"
    SUB_PRODUCT_LINE_FIAT_FIAT_DEPOSIT = "SUB_PRODUCT_LINE_FIAT_FIAT_DEPOSIT"
    SUB_PRODUCT_LINE_FIAT_CREDIT_CARD_PAYMENT_OR_FIAT_DEPOSIT = "SUB_PRODUCT_LINE_FIAT_CREDIT_CARD_PAYMENT_OR_FIAT_DEPOSIT"
    SUB_PRODUCT_LINE_FIAT_QIWI_BALANCE_PAYMENT_FIAT_DEPOSIT = "SUB_PRODUCT_LINE_FIAT_QIWI_BALANCE_PAYMENT_FIAT_DEPOSIT"
    SUB_PRODUCT_LINE_COPY_TRADING_ALL = "SUB_PRODUCT_LINE_COPY_TRADING_ALL"
    SUB_PRODUCT_LINE_COPY_TRADING_CONTRACT_DEFAULT = "SUB_PRODUCT_LINE_COPY_TRADING_CONTRACT_DEFAULT"
    SUB_PRODUCT_LINE_NFT_DEFAULT = "SUB_PRODUCT_LINE_NFT_DEFAULT"
    SUB_PRODUCT_LINE_NFT_FREE_MINT_CARD_DEFAULT = "SUB_PRODUCT_LINE_NFT_FREE_MINT_CARD_DEFAULT"
    SUB_PRODUCT_LINE_BOT_ALL = "SUB_PRODUCT_LINE_BOT_ALL"
    SUB_PRODUCT_LINE_BOT_SPOT_GRID = "SUB_PRODUCT_LINE_BOT_SPOT_GRID"
    SUB_PRODUCT_LINE_BOT_FUTURES_GRID = "SUB_PRODUCT_LINE_BOT_FUTURES_GRID"
    SUB_PRODUCT_LINE_BOT_DCA = "SUB_PRODUCT_LINE_BOT_DCA"
    SUB_PRODUCT_LINE_BOT_FUTURES_MARTINGALE = "SUB_PRODUCT_LINE_BOT_FUTURES_MARTINGALE"
    SUB_PRODUCT_LINE_BOT_FUTURES_COMBO = "SUB_PRODUCT_LINE_BOT_FUTURES_COMBO"
    SUB_PRODUCT_LINE_BYBIT_CARD_DEFAULT = "SUB_PRODUCT_LINE_BYBIT_CARD_DEFAULT"
    SUB_PRODUCT_LINE_P2P_TRADING = "SUB_PRODUCT_LINE_P2P_TRADING"
    SUB_PRODUCT_LINE_EARN_FLEXIBLE_SAVING = "SUB_PRODUCT_LINE_EARN_FLEXIBLE_SAVING"
    SUB_PRODUCT_LINE_BYBIT_PAY = "SUB_PRODUCT_LINE_BYBIT_PAY"


class Award(Base):
    """Reward/coupon record with full lifecycle tracking.

    Composite PK: (id, uid). Rich enum system for categorization.
    """

    __tablename__ = "award"

    id: int = Column(BigInteger, primary_key=True)
    spec_code: str = Column(String, nullable=False)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    can_use: bool = Column(Boolean, nullable=False, default=False)

    status = Column(
        Enum(AwardStatus, name="awardstatus", create_type=False),
        nullable=False,
    )
    using_status = Column(
        Enum(AwardUsingStatus, name="awardusingstatus", create_type=False),
        nullable=False,
    )

    campaign_id: int = Column(BigInteger, nullable=True)
    prize_draw_id: int = Column(Integer, nullable=False, default=0)
    task_id: int = Column(Integer, nullable=False, default=0)
    coin_symbol: str = Column(String, nullable=True)
    description: str = Column(String, nullable=False, default="")

    type = Column(
        Enum(AwardType, name="awardtype", create_type=False),
        nullable=False,
    )
    amount: float = Column(Float, nullable=False, default=0.0)
    amount_unit = Column(
        Enum(AwardAmountUnit, name="awardamountunit", create_type=False),
        nullable=False,
    )
    business_no = Column(
        Enum(BusinessNo, name="businessno", create_type=False),
        nullable=False,
    )
    auto_claim = Column(
        Enum(AutoClaimType, name="autoclaimtype", create_type=False),
        nullable=False,
    )
    product = Column(
        Enum(ProductLine, name="productline", create_type=False),
        nullable=False,
    )
    sub_product = Column(
        Enum(SubProductLine, name="subproductline", create_type=False),
        nullable=False,
    )

    # Usage tracking
    amount_used: float = Column(Float, nullable=False, default=0.0)
    current_amount_used: float = Column(Float, nullable=False, default=0.0)
    total_amount_used: float = Column(Float, nullable=False, default=0.0)
    real_total_amount_used: float = Column(Float, nullable=False, default=0.0)
    remain_amount_used: float = Column(Float, nullable=False, default=0.0)

    # Timestamps
    created_at: datetime = Column(DateTime, nullable=False)
    effective_at: datetime = Column(DateTime, nullable=False)
    ineffective_at: datetime = Column(DateTime, nullable=False)
    award_individual_at: datetime = Column(DateTime, nullable=False)
    last_updated_at: datetime = Column(DateTime, nullable=False)
    awarding_at: datetime = Column(DateTime, nullable=False)

    # Relationship
    account = relationship("BybitAccount", back_populates="awards")

    def __repr__(self) -> str:
        return (
            f"<Award id={self.id} uid={self.uid} "
            f"type={self.type} amount={self.amount} "
            f"status={self.status}>"
        )
