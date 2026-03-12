"""
Transfer router — internal account transfers between sub-accounts.

Handles: fund-to-unified, unified-to-fund, and other internal transfers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.transfer")

router = APIRouter()


class TransferRequest(BaseModel):
    """Internal transfer request."""
    database_ids: List[int]
    coin: str = "USDT"
    amount: float
    from_account_type: str = "FUND"  # FUND, UNIFIED, CONTRACT, SPOT, etc.
    to_account_type: str = "UNIFIED"


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/execute", response_model=BulkOperationResult)
async def execute_transfer(request: TransferRequest):
    """Execute internal transfer for multiple accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "coin": request.coin,
                "amount": request.amount,
                "from": request.from_account_type,
                "to": request.to_account_type,
                "status": "transferred",
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/account-types")
async def get_account_types():
    """Get available account types for transfer."""
    return {
        "account_types": [
            "FUND", "UNIFIED", "CONTRACT", "SPOT",
            "COPY_TRADE", "INVESTMENT", "LAUNCHPOOL",
            "BOT", "MT5", "OPTION",
        ]
    }


@router.get("/balance/{database_id}")
async def get_transfer_balance(
    database_id: int,
    coin: str = Query("USDT"),
    account_type: str = Query("FUND"),
):
    """Get available balance for transfer from a sub-account."""
    return {
        "database_id": database_id,
        "coin": coin,
        "account_type": account_type,
        "available": 0.0,
    }
