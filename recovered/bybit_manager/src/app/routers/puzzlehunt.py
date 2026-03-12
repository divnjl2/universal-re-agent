"""
PuzzleHunt router — puzzle hunt campaign management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.puzzlehunt")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
    """List active puzzle hunt campaigns.

    NOTE: No dedicated list endpoint exists in BasePrivateClient for puzzle hunts.
    Campaigns are discovered by code.
    """
    return {"campaigns": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_puzzlehunt(body: PuzzleHuntRegisterRequest, request: Request):
    """Register accounts for a puzzle hunt."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.join_puzzlehunt_activity(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "registered",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("PuzzleHunt register failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/checkin", response_model=BulkOperationResult)
async def checkin_puzzlehunt(body: PuzzleHuntCheckinRequest, request: Request):
    """Daily check-in for puzzle hunt."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.check_puzzlehunt_activity_daily_task(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "checked_in",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("PuzzleHunt checkin failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_puzzlehunt_status(database_id: int, request: Request, code: int = Query(...)):
    """Get puzzle hunt participation status."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_puzzlehunt_puzzles(code=code)
        return {
            "database_id": database_id,
            "code": code,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
