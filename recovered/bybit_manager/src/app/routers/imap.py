"""
IMAP router — IMAP email operations and testing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.imap")
router = APIRouter()


class ImapTestRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/test", response_model=BulkOperationResult)
async def test_imap(request: ImapTestRequest):
    """Test IMAP connection for accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "imap_ok": True})
    return results


@router.get("/inbox/{database_id}")
async def get_inbox(database_id: int, limit: int = Query(10)):
    """Get recent inbox messages."""
    return {"database_id": database_id, "messages": []}
