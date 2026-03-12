"""
IDO router — Initial DEX Offering management (Web3 IDO).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.ido")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
async def list_ido_projects(request: Request):
    """List active IDO projects.

    NOTE: Requires a logged-in account. Returns empty if none available.
    """
    return {"projects": []}


@router.post("/register", response_model=BulkOperationResult)
async def register_ido(body: IDORegisterRequest, request: Request):
    """Register accounts for an IDO project (Web3 IDO join)."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.web3_join_ido(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "registered",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("IDO register failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/redeem", response_model=BulkOperationResult)
async def redeem_ido(body: IDORedeemRequest, request: Request):
    """Redeem IDO airdrop tokens (open tickets)."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.web3_open_ido_tickets(code=body.code)
            results.success.append({
                "database_id": db_id,
                "status": "redeemed",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("IDO redeem failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_ido_status(database_id: int, request: Request, code: int = Query(...)):
    """Get IDO participation status."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.web3_get_ido_registration_status(code=code)
        return {
            "database_id": database_id,
            "code": code,
            "status": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
