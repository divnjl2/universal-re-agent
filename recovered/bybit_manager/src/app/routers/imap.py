"""
IMAP router — IMAP email operations and testing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.imap")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class ImapTestRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/test", response_model=BulkOperationResult)
async def test_imap(body: ImapTestRequest, request: Request):
    """Test IMAP connection for accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            imap_client = client.get_imap_client()
            await imap_client.connect()
            results.success.append({"database_id": db_id, "imap_ok": True})
        except Exception as e:
            logger.error("IMAP test failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "imap_ok": False,
                "error": str(e),
            })
    return results


@router.get("/inbox/{database_id}")
async def get_inbox(database_id: int, request: Request, limit: int = Query(10)):
    """Get recent inbox messages.

    NOTE: ImapClient.get_recent_messages() would need to be implemented
    for full inbox browsing. Currently only verification code retrieval
    is supported via get_verification_code().
    """
    # TODO: Add get_recent_messages(limit) to ImapClient for full inbox support
    return {"database_id": database_id, "messages": []}
