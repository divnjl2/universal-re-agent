"""
ByVote router — Bybit voting management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.byvote")
router = APIRouter()


class ByVoteRequest(BaseModel):
    database_ids: List[int]
    vote_id: int
    option: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_votes():
    """List active voting campaigns."""
    return {"votes": []}


@router.post("/vote", response_model=BulkOperationResult)
async def submit_vote(request: ByVoteRequest):
    """Submit votes for multiple accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({
            "database_id": db_id,
            "vote_id": request.vote_id,
            "status": "voted",
        })
    return results


@router.get("/status/{database_id}")
async def get_vote_status(database_id: int, vote_id: int = Query(...)):
    """Get voting status for an account."""
    return {"database_id": database_id, "vote_id": vote_id, "status": {}}
