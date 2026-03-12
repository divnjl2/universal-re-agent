"""
ByFi (Earn) router — Bybit savings/earn product management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.byfi")
router = APIRouter()


class ByFiStakeRequest(BaseModel):
    database_ids: List[int]
    product_id: str
    coin: str = "USDT"
    amount: float


class ByFiRedeemRequest(BaseModel):
    database_ids: List[int]
    order_id: str


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/products")
async def list_products(coin: str = Query("USDT")):
    """List earn/savings products."""
    return {"coin": coin, "products": []}


@router.post("/stake", response_model=BulkOperationResult)
async def stake_earn(request: ByFiStakeRequest):
    """Stake in earn product."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({
            "database_id": db_id,
            "amount": request.amount,
            "status": "staked",
        })
    return results


@router.post("/redeem", response_model=BulkOperationResult)
async def redeem_earn(request: ByFiRedeemRequest):
    """Redeem from earn product."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "redeemed"})
    return results


@router.get("/orders/{database_id}")
async def get_earn_orders(
    database_id: int,
    coin: Optional[str] = Query(None),
):
    """Get earn orders for an account."""
    return {"database_id": database_id, "orders": []}
