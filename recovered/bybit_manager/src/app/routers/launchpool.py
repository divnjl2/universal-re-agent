"""
Launchpool router — Bybit Launchpool staking management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.launchpool")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class LaunchpoolStakeRequest(BaseModel):
    database_ids: List[int]
    code: int
    amount: float
    coin: str = "USDT"


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_launchpool_projects():
    """List active launchpool projects.

    NOTE: Requires a logged-in account to fetch. Returns empty if none available.
    """
    return {"projects": []}


@router.post("/stake", response_model=BulkOperationResult)
async def stake_launchpool(body: LaunchpoolStakeRequest, request: Request):
    """Stake tokens in a launchpool project."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.stake_launchpool(
                code=body.code, amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "amount": body.amount,
                "status": "staked",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Launchpool stake failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/unstake", response_model=BulkOperationResult)
async def unstake_launchpool(body: LaunchpoolStakeRequest, request: Request):
    """Unstake tokens from a launchpool project."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.unstake_launchpool(
                code=body.code, amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "status": "unstaked",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Launchpool unstake failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_launchpool_status(database_id: int, request: Request, code: int = Query(...)):
    """Get launchpool participation status."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_launchpool_qualification_status(code=code)
        return {
            "database_id": database_id,
            "code": code,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
