"""
Awarding router — reward/coupon management endpoints.

Handles: list awards, claim awards, use awards, search by status/type.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.awarding")

router = APIRouter()


class ClaimAwardRequest(BaseModel):
    """Claim unclaimed awards."""
    database_ids: List[int]
    award_ids: Optional[List[int]] = None  # None = claim all available


class SearchAwardsRequest(BaseModel):
    """Search awards with filters."""
    database_ids: List[int]
    status: Optional[str] = None
    award_type: Optional[str] = None


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_awards(
    database_id: int = Query(...),
    status: Optional[str] = Query(None),
    page: int = Query(1),
    page_size: int = Query(50),
):
    """List awards for an account."""
    return {"database_id": database_id, "awards": [], "total": 0}


@router.post("/claim", response_model=BulkOperationResult)
async def claim_awards(request: ClaimAwardRequest):
    """Claim unclaimed awards for multiple accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "claimed_count": 0,
                "status": "claimed",
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/search", response_model=BulkOperationResult)
async def search_awards(request: SearchAwardsRequest):
    """Search and sync awards from Bybit API."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "awards_found": 0,
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/summary/{database_id}")
async def award_summary(database_id: int):
    """Get award summary (total value, counts by type/status)."""
    return {
        "database_id": database_id,
        "total_value_usd": 0.0,
        "by_status": {},
        "by_type": {},
    }
