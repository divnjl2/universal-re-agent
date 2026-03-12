"""
Awarding router — reward/coupon management endpoints.

Handles: list awards, claim awards, use awards, search by status/type.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.awarding")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class ClaimAwardRequest(BaseModel):
    """Claim unclaimed awards."""
    database_ids: List[int]
    award_ids: Optional[List[int]] = None  # None = claim all available


class SearchAwardsRequest(BaseModel):
    """Search awards with filters."""
    database_ids: List[int]
    status: Optional[str] = None
    award_type: Optional[str] = None


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/list")
async def list_awards(
    request: Request,
    database_id: int = Query(...),
    status: Optional[str] = Query(None),
    page: int = Query(1),
    page_size: int = Query(50),
):
    """List awards for an account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_rewards(page=page, page_size=page_size)
        result = resp.result if hasattr(resp, "result") else {}
        awards = result if isinstance(result, list) else result.get("records", []) if isinstance(result, dict) else []
        total = len(awards) if isinstance(awards, list) else 0
        return {"database_id": database_id, "awards": awards, "total": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/claim", response_model=BulkOperationResult)
async def claim_awards(body: ClaimAwardRequest, request: Request):
    """Claim unclaimed awards for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            if body.award_ids:
                claimed = 0
                for award_id in body.award_ids:
                    await client.client.claim_reward(award_id=str(award_id))
                    claimed += 1
                results.success.append({
                    "database_id": db_id,
                    "claimed_count": claimed,
                    "status": "claimed",
                })
            else:
                # Claim all via the bulk claim endpoint
                resp = await client.client.claim_all_my_rewards_get_id()
                results.success.append({
                    "database_id": db_id,
                    "status": "claim_all_submitted",
                    "result": resp.result if hasattr(resp, "result") else {},
                })
        except Exception as e:
            logger.error("Claim awards failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/search", response_model=BulkOperationResult)
async def search_awards(body: SearchAwardsRequest, request: Request):
    """Search and sync awards from Bybit API."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.get_rewards(page=1, page_size=50)
            result = resp.result if hasattr(resp, "result") else {}
            awards = result if isinstance(result, list) else result.get("records", []) if isinstance(result, dict) else []
            results.success.append({
                "database_id": db_id,
                "awards_found": len(awards) if isinstance(awards, list) else 0,
            })
        except Exception as e:
            logger.error("Search awards failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/summary/{database_id}")
async def award_summary(database_id: int, request: Request):
    """Get award summary (total value, counts by type/status)."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_rewards(page=1, page_size=100)
        result = resp.result if hasattr(resp, "result") else {}
        awards = result if isinstance(result, list) else result.get("records", []) if isinstance(result, dict) else []
        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        total_value = 0.0
        if isinstance(awards, list):
            for a in awards:
                if isinstance(a, dict):
                    s = a.get("status", "unknown")
                    t = a.get("type", "unknown")
                    by_status[s] = by_status.get(s, 0) + 1
                    by_type[t] = by_type.get(t, 0) + 1
                    total_value += float(a.get("value", 0.0))
        return {
            "database_id": database_id,
            "total_value_usd": total_value,
            "by_status": by_status,
            "by_type": by_type,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
