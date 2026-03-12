"""
Launchpad (IDO) router — Bybit Launchpad project management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.launchpad")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
async def list_launchpad_projects(request: Request):
    """List active launchpad (IDO) projects.

    NOTE: Requires any logged-in account to fetch the list.
    Returns empty if no accounts available.
    """
    # TODO: Could pick first available account to fetch the list
    return {"projects": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_launchpad(body: LaunchpadRegisterRequest, request: Request):
    """Register accounts for a launchpad project."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.join_launchpad(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "registered",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Launchpad register failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/commit", response_model=BulkOperationResult)
async def commit_launchpad(body: LaunchpadCommitRequest, request: Request):
    """Commit tokens to a launchpad project."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.pledge_launchpad(
                code=body.code, amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "amount": body.amount,
                "status": "committed",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Launchpad commit failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_launchpad_status(database_id: int, request: Request, code: int = Query(...)):
    """Get launchpad participation status."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_launchpad_qualifications(code=code)
        return {
            "database_id": database_id,
            "code": code,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
