"""
ByVote router — Bybit voting management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.byvote")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class ByVoteRequest(BaseModel):
    database_ids: List[int]
    vote_id: int
    option: int


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_votes(request: Request):
    """List active voting campaigns.

    NOTE: Requires a logged-in account to fetch vote list from Bybit API.
    Returns empty if no listing endpoint is available.
    """
    return {"votes": []}


@router.post("/vote", response_model=BulkOperationResult)
async def submit_vote(body: ByVoteRequest, request: Request):
    """Submit votes for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.byvote_submit(
                vote_id=body.vote_id,
                option=body.option,
            )
            results.success.append({
                "database_id": db_id,
                "vote_id": body.vote_id,
                "option": body.option,
                "status": "voted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("ByVote submit failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_vote_status(database_id: int, request: Request, vote_id: int = Query(...)):
    """Get voting status for an account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.byvote_get_status(vote_id=vote_id)
        return {
            "database_id": database_id,
            "vote_id": vote_id,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
