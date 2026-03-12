"""
ByFi (Earn) router — Bybit savings/earn product management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.byfi")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
async def list_products(request: Request, coin: str = Query("USDT")):
    """List earn/savings products.

    NOTE: Requires a logged-in account to fetch product list from Bybit API.
    Returns empty if no product listing endpoint is available.
    """
    return {"coin": coin, "products": []}


@router.post("/stake", response_model=BulkOperationResult)
async def stake_earn(body: ByFiStakeRequest, request: Request):
    """Stake in earn product."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.byfi_stake(
                product_id=body.product_id,
                coin=body.coin,
                amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "product_id": body.product_id,
                "amount": body.amount,
                "status": "staked",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("ByFi stake failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/redeem", response_model=BulkOperationResult)
async def redeem_earn(body: ByFiRedeemRequest, request: Request):
    """Redeem from earn product."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.byfi_redeem(
                order_id=body.order_id,
            )
            results.success.append({
                "database_id": db_id,
                "order_id": body.order_id,
                "status": "redeemed",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("ByFi redeem failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/orders/{database_id}")
async def get_earn_orders(
    database_id: int,
    request: Request,
    coin: Optional[str] = Query(None),
):
    """Get earn orders for an account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.byfi_get_orders(coin=coin)
        return {
            "database_id": database_id,
            "orders": resp.result if hasattr(resp, "result") else [],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
