"""
TokenSplash router — token splash campaign management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.tokensplash")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class TokenSplashRegisterRequest(BaseModel):
    database_ids: List[int]
    code: int
    coin_symbol: Optional[str] = None


class TokenSplashVolumeRequest(BaseModel):
    database_ids: List[int]
    code: int
    symbol: str
    amount_usdt: float


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_tokensplash_campaigns():
    """List active token splash campaigns.

    NOTE: No dedicated list endpoint exists in BasePrivateClient for token splash.
    Campaigns are discovered by code.
    """
    return {"campaigns": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_tokensplash(body: TokenSplashRegisterRequest, request: Request):
    """Register accounts for a token splash campaign."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.join_tokensplash(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "registered",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("TokenSplash register failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/make-volume", response_model=BulkOperationResult)
async def make_volume(body: TokenSplashVolumeRequest, request: Request):
    """Execute trading volume for token splash.

    NOTE: Volume generation requires placing spot trades. This delegates
    to the spot trading methods. Full volume automation would need a
    dedicated Manager method.
    """
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            # Buy market order to generate volume
            resp = await client.client.buy_market_order(
                symbol=body.symbol, qty=body.amount_usdt,
            )
            results.success.append({
                "database_id": db_id,
                "volume_usdt": body.amount_usdt,
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("TokenSplash volume failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_tokensplash_status(database_id: int, request: Request, code: int = Query(...)):
    """Get token splash participation status."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_tokensplash_user(code=code)
        return {
            "database_id": database_id,
            "code": code,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
