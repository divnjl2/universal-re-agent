"""
Database-related Pydantic schemas — account CRUD operations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ================================================================
# Account schemas
# ================================================================

class AccountBase(BaseModel):
    """Shared account fields."""
    email_address: str
    password: Optional[str] = None
    group_name: str = "no_group"
    name: Optional[str] = None
    note: Optional[str] = None
    proxy: Optional[str] = None
    preferred_country_code: Optional[str] = None
    inviter_ref_code: Optional[str] = None


class AccountCreate(AccountBase):
    """Create account request."""
    totp_secret: Optional[str] = None
    payment_password: Optional[str] = None
    imap_address: Optional[str] = None
    imap_password: Optional[str] = None
    email_proxy: Optional[str] = None
    cookies: Optional[Dict[str, Any]] = None


class AccountUpdate(BaseModel):
    """Update account request — all fields optional."""
    email_address: Optional[str] = None
    password: Optional[str] = None
    group_name: Optional[str] = None
    name: Optional[str] = None
    note: Optional[str] = None
    proxy: Optional[str] = None
    sumsub_proxy: Optional[str] = None
    onfido_proxy: Optional[str] = None
    aai_proxy: Optional[str] = None
    preferred_country_code: Optional[str] = None
    totp_secret: Optional[str] = None
    payment_password: Optional[str] = None
    inviter_ref_code: Optional[str] = None
    cookies: Optional[Dict[str, Any]] = None
    reported_bad: Optional[bool] = None


class AccountResponse(BaseModel):
    """Account response — full account info."""
    database_id: int
    uid: Optional[int] = None
    email_address: str
    group_name: str = "no_group"
    name: Optional[str] = None
    note: Optional[str] = None

    # Status
    registered: Optional[bool] = None
    is_autoreg: bool = False
    email_verified: Optional[bool] = None
    mobile_verified: Optional[bool] = None
    totp_enabled: Optional[bool] = None
    withdraw_whitelist_enabled: Optional[bool] = None
    is_uta: Optional[bool] = None
    reported_bad: bool = False

    # KYC
    kyc_level: Optional[int] = None
    kyc_status: Optional[str] = None
    country: Optional[str] = None

    # Financial
    balance_usd: float = 0.0
    profit: float = 0.0

    # Proxy
    proxy: Optional[str] = None
    proxy_error: bool = False

    # Referral
    ref_code: Optional[str] = None
    inviter_ref_code: Optional[str] = None

    # Dates
    registered_at: Optional[datetime] = None
    kyc_completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AccountListResponse(BaseModel):
    """Paginated account list."""
    accounts: List[AccountResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50


# ================================================================
# Email schemas
# ================================================================

class EmailCreate(BaseModel):
    """Create email record."""
    address: str
    imap_address: Optional[str] = None
    imap_password: Optional[str] = None
    proxy: Optional[str] = None
    client_id: Optional[str] = None
    refresh_token: Optional[str] = None


class EmailResponse(BaseModel):
    """Email record response."""
    address: str
    imap_address: Optional[str] = None
    proxy_error: bool = False
    last_login_failed: bool = False
    proxy: Optional[str] = None
    has_oauth: bool = False

    model_config = {"from_attributes": True}


# ================================================================
# Import/Export
# ================================================================

class ImportAccountsRequest(BaseModel):
    """Bulk import request."""
    accounts: List[AccountCreate]
    group_name: str = "no_group"


class ExportFormat(BaseModel):
    """Export format config."""
    format: str = "csv"  # csv, json, xlsx
    fields: List[str] = Field(default_factory=lambda: ["database_id", "email_address", "uid", "balance_usd"])
    group_name: Optional[str] = None
