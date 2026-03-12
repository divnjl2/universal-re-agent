"""
BybitAccount model — maps to the shared bybit_account table.

The KYC bot reads from the same bybit_account table that
Bybit Manager v3 writes to. This model is READ-HEAVY for the bot;
only kyc_provider_telegram_username and facial_verification_required
are updated by the bot.

Real SELECT from memory dump (full column list):
  SELECT bybit_account.database_id, bybit_account.uid,
    bybit_account.group_name, bybit_account.name, bybit_account.note,
    bybit_account.email_address, bybit_account.password,
    bybit_account.totp_secret, bybit_account.payment_password,
    bybit_account.kyc_level, bybit_account.kyc_provider_telegram_username,
    bybit_account.ref_code, bybit_account.inviter_ref_code,
    bybit_account.balance_usd, bybit_account.proxy_error,
    bybit_account.proxy_county_restricted, bybit_account.proxy,
    bybit_account.sumsub_proxy, bybit_account.onfido_proxy,
    bybit_account.aai_proxy, ...
    bybit_account.kyc_status, bybit_account.last_provider,
    bybit_account.country, bybit_account.first_name, bybit_account.last_name,
    bybit_account.doc_type, bybit_account.doc_number,
    bybit_account.facial_verification_required, ...
    bybit_account.cookies, bybit_account.reported_bad,
    bybit_account.adspower_profile_id, bybit_account.default_withdraw_address_id

GROUP BY queries:
  SELECT bybit_account.group_name, count(bybit_account.database_id) AS cnt
  SELECT bybit_account.last_login_country_code, count(bybit_account.database_id) AS count_1
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Float, ForeignKey,
    Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import ENUM, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from tg_bot.models.base import Base

# Real ENUMs from Alembic migration 9f17e744cf77 + d305953c4010
kycstatus_enum = ENUM(
    "ALLOW", "NOT_ALLOW", "PENDING", "SUCCESS",
    "FAILED_AND_CAN_RETRY", "FAILED_AND_CAN_NOT_RETRY",
    "CERTIFICATION_DISABLED",
    name="kycstatus", create_type=False,
)

kycprovider_enum = ENUM(
    "PROVIDER_SUMSUB", "PROVIDER_ONFIDO", "PROVIDER_JUMIO",
    "PROVIDER_AAI", "PROVIDER_DEFAULT",
    name="kycprovider", create_type=False,
)


class BybitAccount(Base):
    """
    Shared bybit_account table (also used by Bybit Manager v3).

    Schema matches Alembic migration chain from 9f17e744cf77 through
    4e591d5fac96 (31 migrations total).
    """
    __tablename__ = "bybit_account"

    # Identity
    database_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[Optional[int]] = mapped_column(Integer, unique=True, nullable=True)

    # Group / Name / Note
    group_name: Mapped[str] = mapped_column(
        String(30), server_default="no_group", nullable=False
    )
    name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(String(1500), nullable=True)

    # Secrets
    email_address: Mapped[str] = mapped_column(
        String(254), ForeignKey("email.address"), nullable=False
    )
    password: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(16), unique=True, nullable=True)
    payment_password: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # KYC
    kyc_level: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    kyc_provider_telegram_username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    kyc_status: Mapped[Optional[str]] = mapped_column(kycstatus_enum, nullable=True)
    last_provider: Mapped[Optional[str]] = mapped_column(kycprovider_enum, nullable=True)
    kyc_conflict: Mapped[bool] = mapped_column(Boolean, server_default="FALSE", nullable=False)
    kyc_conflict_uid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    need_questionnaire: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    facial_verification_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # KYC details
    first_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    doc_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    doc_number: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # Referral
    ref_code: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    inviter_ref_code: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # Balance (renamed from 'balance' -> 'balance_usd' in migration b239907a4191)
    balance_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    profit: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Proxy
    proxy: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    proxy_error: Mapped[bool] = mapped_column(Boolean, server_default="FALSE", nullable=False)
    proxy_county_restricted: Mapped[bool] = mapped_column(Boolean, server_default="FALSE", nullable=False)
    proxy_payment_required: Mapped[bool] = mapped_column(Boolean, server_default="FALSE", nullable=False)
    sumsub_proxy: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    onfido_proxy: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    aai_proxy: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # Login / Device
    preferred_country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    last_login_country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    chrome_major_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    screen_width: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    screen_height: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_tencent_request_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Participation flags
    can_participate_demo_trading_tournament: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    can_participate_tokensplash: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    can_participate_airdrophunt: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    can_participate_launchpool: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    can_participate_puzzlehunt: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    ido_risk_control: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # Status flags
    registered: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    is_autoreg: Mapped[bool] = mapped_column(Boolean, server_default="FALSE", nullable=False)
    email_verified: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    mobile_verified: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    totp_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    withdraw_whitelist_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    is_uta: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    reported_bad: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # Web3
    web3_cloud_wallets_created: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    web3_mnemonic_phrase: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True)
    web3_ido_ton_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    twitter_auth_token: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    twitter_bind_code: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # Timestamps
    registered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    kyc_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Other
    adspower_profile_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_withdraw_address_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cookies: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<BybitAccount(db_id={self.database_id}, uid={self.uid}, "
            f"group={self.group_name}, kyc={self.kyc_status})>"
        )
