"""
Spot trading router — endpoints for spot market operations.

Handles: buy/sell market/limit orders, open orders, order history, cancel.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.spot")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class SpotOrderRequest(BaseModel):
    """Spot order request."""
    database_ids: List[int]
    symbol: str  # e.g. "BTCUSDT"
    side: str  # "buy" or "sell"
    order_type: str = "market"  # "market" or "limit"
    amount: float
    price: Optional[float] = None  # Required for limit orders


class CancelOrderRequest(BaseModel):
    """Cancel order request."""
    database_ids: List[int]
    symbol: str
    order_id: Optional[str] = None  # None = cancel all


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/buy-market", response_model=BulkOperationResult)
async def spot_buy_market(body: SpotOrderRequest, request: Request):
    """Execute spot market buy for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.buy_market_order(
                symbol=body.symbol, qty=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "buy",
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Spot buy market failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/sell-market", response_model=BulkOperationResult)
async def spot_sell_market(body: SpotOrderRequest, request: Request):
    """Execute spot market sell for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.sell_market_order(
                symbol=body.symbol, qty=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "sell",
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Spot sell market failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/buy-limit", response_model=BulkOperationResult)
async def spot_buy_limit(body: SpotOrderRequest, request: Request):
    """Execute spot limit buy."""
    if body.price is None:
        raise HTTPException(400, "price required for limit order")
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.buy_limit_order(
                symbol=body.symbol, qty=body.amount, price=body.price,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "buy",
                "price": body.price,
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Spot buy limit failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/sell-limit", response_model=BulkOperationResult)
async def spot_sell_limit(body: SpotOrderRequest, request: Request):
    """Execute spot limit sell."""
    if body.price is None:
        raise HTTPException(400, "price required for limit order")
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.sell_limit_order(
                symbol=body.symbol, qty=body.amount, price=body.price,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "sell",
                "price": body.price,
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Spot sell limit failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/cancel", response_model=BulkOperationResult)
async def cancel_orders(body: CancelOrderRequest, request: Request):
    """Cancel spot orders."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            if body.order_id:
                resp = await client.client.cancel_order(
                    order_id=body.order_id, symbol=body.symbol,
                )
            else:
                resp = await client.client.cancel_all_orders(symbol=body.symbol)
            results.success.append({
                "database_id": db_id,
                "status": "cancelled",
            })
        except Exception as e:
            logger.error("Cancel order failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/open-orders")
async def get_open_orders(
    request: Request,
    database_id: int = Query(...),
    symbol: Optional[str] = Query(None),
):
    """Get open spot orders."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_open_orders(symbol=symbol or "")
        return {
            "database_id": database_id,
            "orders": resp.result or [],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/order-history")
async def get_order_history(
    request: Request,
    database_id: int = Query(...),
    symbol: Optional[str] = Query(None),
    page: int = Query(1),
):
    """Get spot order history."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_order_history(
            symbol=symbol or "", limit=50,
        )
        result = resp.result if hasattr(resp, "result") else {}
        orders = result if isinstance(result, list) else result.get("orders", []) if isinstance(result, dict) else []
        total = len(orders) if isinstance(orders, list) else 0
        return {"database_id": database_id, "orders": orders, "total": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
