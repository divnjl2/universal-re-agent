"""
Common Pydantic schemas for private API operations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DatabaseIdListRequest(BaseModel):
    """Base request with list of database IDs."""
    database_ids: List[int]
    concurrency: int = 5


class BulkResult(BaseModel):
    """Bulk operation result."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.success) + len(self.failed)


class LoginRequest(DatabaseIdListRequest):
    """Login request."""
    pass


class RegisterRequest(DatabaseIdListRequest):
    """Register request."""
    ref_code: str = ""
    country_code: str = ""


class ProfileRequest(DatabaseIdListRequest):
    """Profile fetch request."""
    pass


class BalanceCheckRequest(DatabaseIdListRequest):
    """Balance check request."""
    pass


class Enable2FARequest(DatabaseIdListRequest):
    """Enable 2FA request."""
    pass


class Disable2FARequest(DatabaseIdListRequest):
    """Disable 2FA request."""
    pass


class ChangePasswordRequest(DatabaseIdListRequest):
    """Change password request."""
    new_password: str


class WithdrawRequest(BaseModel):
    """Withdrawal request."""
    database_ids: List[int]
    coin: str = "USDT"
    chain: str = "APTOS"
    address: str
    amount: float
    withdraw_type: int = 0


class TransferRequest(BaseModel):
    """Internal transfer request."""
    database_ids: List[int]
    coin: str = "USDT"
    amount: float
    from_account_type: str = "FUND"
    to_account_type: str = "UNIFIED"
