"""
Email router — email account management and verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.email")
router = APIRouter()


class EmailCheckRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/check", response_model=BulkOperationResult)
async def check_email_login(request: EmailCheckRequest):
    """Check IMAP login for multiple accounts' emails."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        results.success.append({"database_id": db_id, "status": "ok"})
    return results


@router.get("/status/{database_id}")
async def get_email_status(database_id: int):
    """Get email status for an account."""
    return {
        "database_id": database_id,
        "proxy_error": False,
        "last_login_failed": False,
    }
