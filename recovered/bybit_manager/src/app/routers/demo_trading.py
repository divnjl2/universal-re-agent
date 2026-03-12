"""
Demo trading router — demo trading tournament management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.demo_trading")
router = APIRouter()


class DemoTradingRegisterRequest(BaseModel):
    database_ids: List[int]
    tournament_id: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/tournaments")
async def list_tournaments():
    """List active demo trading tournaments."""
    return {"tournaments": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_tournament(request: DemoTradingRegisterRequest):
    """Register accounts for a demo trading tournament."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "registered"})
    return results


@router.get("/status/{database_id}")
async def get_tournament_status(
    database_id: int,
    tournament_id: int = Query(...),
):
    """Get tournament participation status."""
    return {"database_id": database_id, "tournament_id": tournament_id, "status": {}}
