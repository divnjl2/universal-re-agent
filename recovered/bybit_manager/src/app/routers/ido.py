"""
IDO router — Initial DEX Offering management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.ido")
router = APIRouter()


class IDORegisterRequest(BaseModel):
    database_ids: List[int]
    code: int


class IDORedeemRequest(BaseModel):
    database_ids: List[int]
    code: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_ido_projects():
    """List active IDO projects."""
    return {"projects": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_ido(request: IDORegisterRequest):
    """Register accounts for an IDO project."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "registered"})
    return results


@router.post("/redeem", response_model=BulkOperationResult)
async def redeem_ido(request: IDORedeemRequest):
    """Redeem IDO airdrop tokens."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "redeemed"})
    return results


@router.get("/status/{database_id}")
async def get_ido_status(database_id: int, code: int = Query(...)):
    """Get IDO participation status."""
    return {"database_id": database_id, "code": code, "status": {}}
