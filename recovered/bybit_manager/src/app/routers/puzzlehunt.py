"""
PuzzleHunt router — puzzle hunt campaign management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.puzzlehunt")
router = APIRouter()


class PuzzleHuntRegisterRequest(BaseModel):
    database_ids: List[int]
    code: int


class PuzzleHuntCheckinRequest(BaseModel):
    database_ids: List[int]
    code: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_puzzlehunt_campaigns():
    """List active puzzle hunt campaigns."""
    return {"campaigns": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_puzzlehunt(request: PuzzleHuntRegisterRequest):
    """Register accounts for a puzzle hunt."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "registered"})
    return results


@router.post("/checkin", response_model=BulkOperationResult)
async def checkin_puzzlehunt(request: PuzzleHuntCheckinRequest):
    """Daily check-in for puzzle hunt."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "checked_in"})
    return results


@router.get("/status/{database_id}")
async def get_puzzlehunt_status(database_id: int, code: int = Query(...)):
    """Get puzzle hunt participation status."""
    return {"database_id": database_id, "code": code, "status": {}}
