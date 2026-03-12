"""
Web3 activity router — IDO, airdrops, and other web3 activities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.web3.activity")
router = APIRouter()


class Web3IDORequest(BaseModel):
    database_ids: List[int]
    project_id: str


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/ido/list")
async def list_web3_idos():
    """List active web3 IDO projects."""
    return {"projects": []}


@router.post("/ido/register", response_model=BulkOperationResult)
async def register_web3_ido(request: Web3IDORequest):
    """Register for a web3 IDO."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "registered"})
    return results


@router.get("/airdrops")
async def list_web3_airdrops():
    """List web3 airdrops."""
    return {"airdrops": []}
