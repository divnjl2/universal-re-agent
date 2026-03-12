"""
Launchpad (IDO) router — Bybit Launchpad project management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.launchpad")
router = APIRouter()


class LaunchpadRegisterRequest(BaseModel):
    database_ids: List[int]
    code: int


class LaunchpadCommitRequest(BaseModel):
    database_ids: List[int]
    code: int
    amount: float


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_launchpad_projects():
    """List active launchpad (IDO) projects."""
    return {"projects": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_launchpad(request: LaunchpadRegisterRequest):
    """Register accounts for a launchpad project."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "registered"})
    return results


@router.post("/commit", response_model=BulkOperationResult)
async def commit_launchpad(request: LaunchpadCommitRequest):
    """Commit tokens to a launchpad project."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({
            "database_id": db_id,
            "amount": request.amount,
            "status": "committed",
        })
    return results


@router.get("/status/{database_id}")
async def get_launchpad_status(database_id: int, code: int = Query(...)):
    """Get launchpad participation status."""
    return {"database_id": database_id, "code": code, "status": {}}
