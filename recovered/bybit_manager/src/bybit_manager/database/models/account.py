"""
SQLAlchemy ORM model for bybit_account table — recovered from Alembic migrations.

This is the ROOT entity. All other tables FK to bybit_account.uid.
Schema matches migration 2024_12_27_2000-9f17e744cf77_v3.py + subsequent migrations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer,
    String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .base import Base


class BybitAccount(Base):
    """
    Core account table — matches bybit_account in PostgreSQL.
    PK: database_id, unique: uid, totp_secret.
    """
    __tablename__ = "bybit_account"

    # Identity
    database_id = Column(Integer, primary_key=True)
    uid = Column(Integer, unique=True, nullable=True)
    member_id = Column(String, nullable=True)
    email_address = Column(String(254), ForeignKey("email.address"), nullable=False)

    # Group, Name, Note
    group_name = Column(String(30), server_default="no_group", nullable=False)
    name = Column(String(100), nullable=True)
    note = Column(String(1500), nullable=True)

    # Secrets
    password = Column(String(128), nullable=True)
    totp_secret = Column(String(16), unique=True, nullable=True)
    payment_password = Column(String(30), nullable=True)

    # KYC
    kyc_level = Column(Integer, nullable=True)
    kyc_status = Column(
        Enum(
            "ALLOW", "NOT_ALLOW", "PENDING", "SUCCESS",
            "FAILED_AND_CAN_RETRY", "FAILED_AND_CAN_NOT_RETRY",
            "CERTIFICATION_DISABLED",
            name="kycstatus",
            create_type=False,
        ),
        nullable=True,
    )
    last_provider = Column(
        Enum(
            "PROVIDER_SUMSUB", "PROVIDER_ONFIDO", "PROVIDER_JUMIO",
            "PROVIDER_AAI", "PROVIDER_DEFAULT",
            name="kycprovider",
            create_type=False,
        ),
        nullable=True,
    )
    kyc_conflict = Column(Boolean, server_default="FALSE", nullable=False)
    kyc_conflict_uid = Column(Integer, nullable=True)
    kyc_provider_telegram_username = Column(String, nullable=True)
    facial_verification_required = Column(Boolean, nullable=True)
    need_questionnaire = Column(Boolean, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    doc_type = Column(String, nullable=True)
    doc_number = Column(String, nullable=True)
    country = Column(String, nullable=True)

    # Financial
    total_balance_btc = Column(Float, nullable=True)
    balance_usd = Column(Float, server_default="0", nullable=False)
    profit = Column(Float, server_default="0", nullable=False)

    # Web3
    web3_cloud_wallets_created = Column(Boolean, nullable=True)
    web3_mnemonic_phrase = Column(String, unique=True, nullable=True)
    web3_ido_ton_address = Column(String, nullable=True)
    twitter_auth_token = Column(String, nullable=True)
    twitter_bind_code = Column(String, nullable=True)

    # Proxy
    proxy = Column(String, nullable=True)
    proxy_provider = Column(String, nullable=True)
    proxy_country = Column(String(2), nullable=True)
    proxy_session_id = Column(String, nullable=True)
    proxy_error = Column(Boolean, server_default="FALSE", nullable=False)
    proxy_county_restricted = Column(Boolean, server_default="FALSE", nullable=False)
    proxy_payment_required = Column(Boolean, server_default="FALSE", nullable=False)
    sumsub_proxy = Column(String, nullable=True)
    onfido_proxy = Column(String, nullable=True)
    aai_proxy = Column(String, nullable=True)

    # Device / Login
    guid = Column(String(36), nullable=True)
    device_id = Column(String(36), nullable=True)
    preferred_country_code = Column(String(2), nullable=True)
    last_login_country_code = Column(String(2), nullable=True)
    last_login_ip = Column(String, nullable=True)
    chrome_major_version = Column(Integer, nullable=True)
    os = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    screen_width = Column(Integer, nullable=True)
    screen_height = Column(Integer, nullable=True)
    last_tencent_request_time = Column(DateTime, nullable=True)

    # Status flags
    registered = Column(Boolean, nullable=True)
    is_autoreg = Column(Boolean, server_default="FALSE", nullable=False)
    email_verified = Column(Boolean, nullable=True)
    mobile_verified = Column(Boolean, nullable=True)
    totp_enabled = Column(Boolean, nullable=True)
    withdraw_whitelist_enabled = Column(Boolean, nullable=True)
    is_uta = Column(Boolean, nullable=True)
    reported_bad = Column(Boolean, server_default="FALSE", nullable=False)

    # Participation flags
    can_participate_demo_trading_tournament = Column(Boolean, nullable=True)
    can_participate_tokensplash = Column(Boolean, nullable=True)
    can_participate_airdrophunt = Column(Boolean, nullable=True)
    can_participate_launchpool = Column(Boolean, nullable=True)
    can_participate_puzzlehunt = Column(Boolean, nullable=True)
    ido_risk_control = Column(Boolean, nullable=True)

    # Referral
    ref_code = Column(String, nullable=True)
    inviter_ref_code = Column(String, nullable=True)

    # Other
    adspower_profile_id = Column(String, nullable=True)
    default_withdraw_address_id = Column(Integer, nullable=True)
    cookies = Column(JSONB, nullable=True)
    registered_at = Column(DateTime, nullable=True)
    kyc_completed_at = Column(DateTime, nullable=True)

    # Relationships
    email = relationship("Email", back_populates="account", uselist=False, lazy="joined")
    finance_accounts = relationship("FinanceAccount", back_populates="account", cascade="all, delete-orphan")
    deposit_history = relationship("DepositHistory", back_populates="account", cascade="all, delete-orphan")
    withdraw_history = relationship("WithdrawHistory", back_populates="account", cascade="all, delete-orphan")
    deposit_addresses = relationship("DepositAddress", back_populates="account", cascade="all, delete-orphan")
    withdraw_addresses = relationship("WithdrawAddress", back_populates="account", cascade="all, delete-orphan")
    awards = relationship("Award", back_populates="account", cascade="all, delete-orphan")
    airdrophunts = relationship("AirdropHunt", back_populates="account", cascade="all, delete-orphan")
    tokensplashes = relationship("TokenSplash", back_populates="account", cascade="all, delete-orphan")
    puzzlehunts = relationship("PuzzleHunt", back_populates="account", cascade="all, delete-orphan")
    idos = relationship("IDO", back_populates="account", cascade="all, delete-orphan")
    web3_wallets = relationship("Web3Wallet", back_populates="account", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<BybitAccount(database_id={self.database_id}, uid={self.uid}, email={self.email_address})>"
