"""
Base Pydantic schemas — shared request/response models for the API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ================================================================
# Generic response wrappers
# ================================================================

class StatusResponse(BaseModel):
    """Simple status response."""
    status: str = "ok"
    message: str = ""


class ErrorResponse(BaseModel):
    """Error response."""
    status: str = "error"
    message: str
    detail: Optional[str] = None


class BulkOperationResult(BaseModel):
    """Result of a bulk operation across multiple accounts."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.success) + len(self.failed)

    @property
    def success_count(self) -> int:
        return len(self.success)

    @property
    def failed_count(self) -> int:
        return len(self.failed)


class PaginatedResponse(BaseModel):
    """Paginated list response."""
    items: List[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50


# ================================================================
# Account identifiers
# ================================================================

class DatabaseIdList(BaseModel):
    """Request body containing a list of database_ids."""
    database_ids: List[int]


class AccountIdentifier(BaseModel):
    """Single account identifier."""
    database_id: int


# ================================================================
# Common field schemas
# ================================================================

class CoinChainPair(BaseModel):
    """Coin + chain pair."""
    coin: str = "USDT"
    chain: str = "APTOS"


class AmountField(BaseModel):
    """Amount with optional precision."""
    amount: float
    precision: Optional[int] = None
