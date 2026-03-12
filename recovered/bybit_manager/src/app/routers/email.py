"""
Email router — email account management and verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.email")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class EmailCheckRequest(BaseModel):
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/check", response_model=BulkOperationResult)
async def check_email_login(body: EmailCheckRequest, request: Request):
    """Check IMAP login for multiple accounts' emails."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            imap_client = client.get_imap_client()
            await imap_client.connect()
            results.success.append({"database_id": db_id, "status": "ok"})
        except Exception as e:
            logger.error("Email check failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_email_status(database_id: int, request: Request):
    """Get email status for an account."""
    manager = _get_manager(request)
    try:
        account = await manager.get_account(database_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")
        return {
            "database_id": database_id,
            "email_address": account.email_address,
            "email_verified": getattr(account, "email_verified", None),
            "proxy_error": getattr(account, "proxy_error", False),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
