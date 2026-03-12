"""
Referral router — referral code and commission management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.referral")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class ReferralCodeRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/get-codes", response_model=BulkOperationResult)
async def get_referral_codes(body: ReferralCodeRequest, request: Request):
    """Fetch referral codes for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            ref_code = await client.client.get_referral_code()
            # PrivateClient.get_referral_code() returns a string
            results.success.append({"database_id": db_id, "ref_code": ref_code})
        except Exception as e:
            logger.error("Get referral code failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/code/{database_id}")
async def get_referral_code(database_id: int, request: Request):
    """Get referral code for one account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        ref_code = await client.client.get_referral_code()
        return {"database_id": database_id, "ref_code": ref_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/commission/{database_id}")
async def get_referral_commission(database_id: int, request: Request):
    """Get referral commission info."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_referral_commission_info()
        return {
            "database_id": database_id,
            "commission": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
