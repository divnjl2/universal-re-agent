"""
Referral router — referral code and commission management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.referral")
router = APIRouter()


class ReferralCodeRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/get-codes", response_model=BulkOperationResult)
async def get_referral_codes(request: ReferralCodeRequest):
    """Fetch referral codes for multiple accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "ref_code": ""})
    return results


@router.get("/code/{database_id}")
async def get_referral_code(database_id: int):
    """Get referral code for one account."""
    return {"database_id": database_id, "ref_code": ""}


@router.get("/commission/{database_id}")
async def get_referral_commission(database_id: int):
    """Get referral commission info."""
    return {"database_id": database_id, "commission": {}}
