"""
Bybit award/reward models — recovered from memory dump + DB schema.

Award enums from DB:
- awardstatus: UNCLAIMED, CLAIMED, PENDING, UNKNOWN, UNCLAIMED_EXPIRED
- awardusingstatus: UNKNOWN, PENDING, IN_USE, FINISHED, FAILURE, TRANSFER, EXPIRED
- awardtype: 20+ values (CASH_VOUCHER, SPOT_DISCOUNT, LEVERAGE_BONUS, etc.)
- awardamountunit: USD, COIN
- autoclaimtype: UNKNOWN, YES, NO
- productline: 17 values
- subproductline: 37+ values
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AwardStatus(str, Enum):
    UNCLAIMED = "UNCLAIMED"
    CLAIMED = "CLAIMED"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"
    UNCLAIMED_EXPIRED = "UNCLAIMED_EXPIRED"


class AwardUsingStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    IN_USE = "IN_USE"
    FINISHED = "FINISHED"
    FAILURE = "FAILURE"
    TRANSFER = "TRANSFER"
    EXPIRED = "EXPIRED"


class AwardAmountUnit(str, Enum):
    USD = "USD"
    COIN = "COIN"


class AutoClaimType(str, Enum):
    UNKNOWN = "UNKNOWN"
    YES = "YES"
    NO = "NO"


class Award(BaseModel):
    """
    Award/reward record — matches award table in DB.
    PK: (id, uid, spec_code)
    """
    id: str = ""
    uid: int = 0
    spec_code: str = ""
    award_type: str = ""
    title: str = ""
    description: str = ""
    status: str = ""
    using_status: str = ""
    amount: float = 0.0
    used_amount: float = 0.0
    amount_unit: str = "USD"
    coin: str = ""
    product_line: str = ""
    sub_product_line: str = ""
    auto_claim: str = "NO"
    business_no: str = ""
    expire_at: Optional[str] = None
    claimed_at: Optional[str] = None
    created_at: Optional[str] = None

    class Config:
        extra = "allow"


class AwardSearchResponse(BaseModel):
    """Response for award search (search-together endpoint)."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[List[Award]] = None
    total: int = 0
    page: int = 1
    page_size: int = 20
