"""
Demo trading router — demo trading tournament management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.demo_trading")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class DemoTradingRegisterRequest(BaseModel):
    database_ids: List[int]
    tournament_id: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/tournaments")
async def list_tournaments():
    """List active demo trading tournaments.

    NOTE: No dedicated list endpoint exists in BasePrivateClient.
    Tournaments are discovered by code/ID.
    """
    return {"tournaments": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_tournament(body: DemoTradingRegisterRequest, request: Request):
    """Register accounts for a demo trading tournament."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.register_demo_trading_tournament(
                code=body.tournament_id,
            )
            results.success.append({
                "database_id": db_id,
                "status": "registered",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Demo trading register failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_tournament_status(
    database_id: int,
    request: Request,
    tournament_id: int = Query(...),
):
    """Get tournament participation status.

    NOTE: No dedicated status endpoint in BasePrivateClient for demo trading.
    """
    # TODO: Add get_demo_trading_tournament_status() to BasePrivateClient
    return {"database_id": database_id, "tournament_id": tournament_id, "status": {}}
