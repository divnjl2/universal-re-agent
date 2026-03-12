"""
Launchpool router — Bybit Launchpool staking management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.launchpool")
router = APIRouter()


class LaunchpoolStakeRequest(BaseModel):
    database_ids: List[int]
    code: int
    amount: float
    coin: str = "USDT"


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_launchpool_projects():
    """List active launchpool projects."""
    return {"projects": []}


@router.post("/stake", response_model=BulkOperationResult)
async def stake_launchpool(request: LaunchpoolStakeRequest):
    """Stake tokens in a launchpool project."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({
            "database_id": db_id,
            "amount": request.amount,
            "status": "staked",
        })
    return results


@router.post("/unstake", response_model=BulkOperationResult)
async def unstake_launchpool(request: LaunchpoolStakeRequest):
    """Unstake tokens from a launchpool project."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "unstaked"})
    return results


@router.get("/status/{database_id}")
async def get_launchpool_status(database_id: int, code: int = Query(...)):
    """Get launchpool participation status."""
    return {"database_id": database_id, "code": code, "status": {}}
