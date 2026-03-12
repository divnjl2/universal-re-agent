"""
Contract trading router — endpoints for perpetual/futures operations.

Handles: open/close positions, leverage, TP/SL, order management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.contract")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class ContractOrderRequest(BaseModel):
    """Contract order request."""
    database_ids: List[int]
    symbol: str
    side: str  # "buy" or "sell"
    order_type: str = "market"
    qty: float
    price: Optional[float] = None
    leverage: int = 1
    take_profit: Optional[float] = None
    stop_loss: Optional[float] = None


class SetLeverageRequest(BaseModel):
    """Set leverage request."""
    database_ids: List[int]
    symbol: str
    leverage: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/open-long", response_model=BulkOperationResult)
async def open_long(body: ContractOrderRequest, request: Request):
    """Open long position."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.create_contract_order(
                symbol=body.symbol,
                side="Buy",
                order_type=body.order_type.capitalize(),
                qty=body.qty,
                price=body.price,
                leverage=body.leverage,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "long",
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Open long failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/open-short", response_model=BulkOperationResult)
async def open_short(body: ContractOrderRequest, request: Request):
    """Open short position."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.create_contract_order(
                symbol=body.symbol,
                side="Sell",
                order_type=body.order_type.capitalize(),
                qty=body.qty,
                price=body.price,
                leverage=body.leverage,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "side": "short",
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Open short failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/close", response_model=BulkOperationResult)
async def close_position(body: ContractOrderRequest, request: Request):
    """Close an open position by opening opposite side."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    # Close = open opposite side with same qty
    close_side = "Sell" if body.side.lower() == "buy" else "Buy"
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.create_contract_order(
                symbol=body.symbol,
                side=close_side,
                order_type="Market",
                qty=body.qty,
                leverage=body.leverage,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "status": "closed",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Close position failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/set-leverage", response_model=BulkOperationResult)
async def set_leverage(body: SetLeverageRequest, request: Request):
    """Set leverage for a symbol."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.set_leverage(
                symbol=body.symbol,
                leverage=body.leverage,
            )
            results.success.append({
                "database_id": db_id,
                "symbol": body.symbol,
                "leverage": body.leverage,
            })
        except Exception as e:
            logger.error("Set leverage failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/positions")
async def get_positions(
    request: Request,
    database_id: int = Query(...),
    symbol: Optional[str] = Query(None),
):
    """Get open positions.

    NOTE: BasePrivateClient does not expose a get_contract_positions method.
    This would need a dedicated method added to the client.
    """
    # TODO: Add get_contract_positions() to BasePrivateClient
    return {"database_id": database_id, "positions": []}


@router.get("/open-orders")
async def get_open_orders(
    request: Request,
    database_id: int = Query(...),
    symbol: Optional[str] = Query(None),
):
    """Get open contract orders."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_open_perp_orders(symbol=symbol or "")
        return {
            "database_id": database_id,
            "orders": resp.result or [],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
