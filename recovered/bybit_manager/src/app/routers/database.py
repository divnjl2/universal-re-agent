"""
Database router — CRUD endpoints for account and email management.

Handles: account listing, creation, update, deletion, import/export,
group management, and email record management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.database")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


# ================================================================
# Request/Response schemas
# ================================================================

class AccountCreateRequest(BaseModel):
    """Create a single account."""
    email_address: str
    password: Optional[str] = None
    group_name: str = "no_group"
    name: Optional[str] = None
    proxy: Optional[str] = None
    totp_secret: Optional[str] = None
    payment_password: Optional[str] = None
    imap_address: Optional[str] = None
    imap_password: Optional[str] = None
    preferred_country_code: Optional[str] = None
    inviter_ref_code: Optional[str] = None


class AccountUpdateRequest(BaseModel):
    """Update account fields."""
    password: Optional[str] = None
    group_name: Optional[str] = None
    name: Optional[str] = None
    note: Optional[str] = None
    proxy: Optional[str] = None
    sumsub_proxy: Optional[str] = None
    onfido_proxy: Optional[str] = None
    aai_proxy: Optional[str] = None
    totp_secret: Optional[str] = None
    payment_password: Optional[str] = None
    preferred_country_code: Optional[str] = None
    reported_bad: Optional[bool] = None
    cookies: Optional[Dict[str, Any]] = None


class BulkImportRequest(BaseModel):
    """Import multiple accounts."""
    accounts: List[AccountCreateRequest]
    group_name: str = "no_group"


class BulkDeleteRequest(BaseModel):
    """Delete multiple accounts."""
    database_ids: List[int]


class AccountResponse(BaseModel):
    """Account info response."""
    database_id: int
    uid: Optional[int] = None
    email_address: str
    group_name: str = "no_group"
    name: Optional[str] = None
    note: Optional[str] = None
    registered: Optional[bool] = None
    balance_usd: float = 0.0
    proxy: Optional[str] = None
    proxy_error: bool = False
    kyc_level: Optional[int] = None
    kyc_status: Optional[str] = None
    totp_enabled: Optional[bool] = None
    ref_code: Optional[str] = None

    model_config = {"from_attributes": True}


class BulkOperationResult(BaseModel):
    """Result of bulk operations."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


# ================================================================
# Endpoints
# ================================================================

@router.get("/accounts")
async def list_accounts(
    request: Request,
    group_name: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """List accounts with pagination and optional group filter."""
    manager = _get_manager(request)
    accounts, total = await manager.get_accounts(
        group_name=group_name, page=page, page_size=page_size,
    )
    return {
        "accounts": [
            AccountResponse.model_validate(a).model_dump() for a in accounts
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/accounts/{database_id}")
async def get_account(database_id: int, request: Request):
    """Get single account by database_id."""
    manager = _get_manager(request)
    account = await manager.get_account(database_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return AccountResponse.model_validate(account).model_dump()


@router.post("/accounts", response_model=AccountResponse)
async def create_account(body: AccountCreateRequest, request: Request):
    """Create a new account."""
    manager = _get_manager(request)
    account = await manager.create_account(
        email_address=body.email_address,
        password=body.password,
        group_name=body.group_name,
        proxy=body.proxy,
        imap_address=body.imap_address,
        imap_password=body.imap_password,
        totp_secret=body.totp_secret,
        payment_password=body.payment_password,
        preferred_country_code=body.preferred_country_code,
        inviter_ref_code=body.inviter_ref_code,
    )
    return AccountResponse.model_validate(account)


@router.put("/accounts/{database_id}")
async def update_account(database_id: int, body: AccountUpdateRequest, request: Request):
    """Update an existing account."""
    manager = _get_manager(request)
    fields = body.model_dump(exclude_none=True)
    account = await manager.update_account(database_id, **fields)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return AccountResponse.model_validate(account).model_dump()


@router.delete("/accounts/{database_id}")
async def delete_account(database_id: int, request: Request):
    """Delete a single account."""
    manager = _get_manager(request)
    count = await manager.delete_accounts([database_id])
    if count == 0:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"database_id": database_id, "status": "deleted"}


@router.post("/accounts/import", response_model=BulkOperationResult)
async def import_accounts(body: BulkImportRequest, request: Request):
    """Bulk import accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for acc in body.accounts:
        try:
            account = await manager.create_account(
                email_address=acc.email_address,
                password=acc.password,
                group_name=acc.group_name or body.group_name,
                proxy=acc.proxy,
                imap_address=acc.imap_address,
                imap_password=acc.imap_password,
                totp_secret=acc.totp_secret,
                payment_password=acc.payment_password,
                preferred_country_code=acc.preferred_country_code,
                inviter_ref_code=acc.inviter_ref_code,
            )
            results.success.append({
                "database_id": account.database_id,
                "email_address": acc.email_address,
                "status": "imported",
            })
        except Exception as e:
            results.failed.append({
                "email_address": acc.email_address,
                "error": str(e),
            })
    return results


@router.post("/accounts/delete", response_model=BulkOperationResult)
async def bulk_delete_accounts(body: BulkDeleteRequest, request: Request):
    """Bulk delete accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    count = await manager.delete_accounts(body.database_ids)
    for db_id in body.database_ids:
        results.success.append({
            "database_id": db_id,
            "status": "deleted",
        })
    return results


@router.get("/groups")
async def list_groups(request: Request):
    """List all account groups with counts."""
    manager = _get_manager(request)
    accounts, total = await manager.get_accounts(page=1, page_size=10000)
    groups: Dict[str, int] = {}
    for acc in accounts:
        g = getattr(acc, "group_name", "no_group") or "no_group"
        groups[g] = groups.get(g, 0) + 1
    return {"groups": groups}


@router.put("/accounts/{database_id}/group")
async def change_group(database_id: int, request: Request, group_name: str = Query(...)):
    """Move account to a different group."""
    manager = _get_manager(request)
    account = await manager.update_account(database_id, group_name=group_name)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"database_id": database_id, "group_name": group_name}


@router.get("/accounts/{database_id}/cookies")
async def get_cookies(database_id: int, request: Request):
    """Get account cookies (for debugging)."""
    manager = _get_manager(request)
    account = await manager.get_account(database_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"database_id": database_id, "cookies": account.cookies or {}}


@router.put("/accounts/{database_id}/cookies")
async def update_cookies(database_id: int, cookies: Dict[str, Any], request: Request):
    """Update account cookies."""
    manager = _get_manager(request)
    account = await manager.update_account(database_id, cookies=cookies)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"database_id": database_id, "status": "updated"}


@router.get("/stats")
async def get_stats(request: Request):
    """Get database statistics."""
    manager = _get_manager(request)
    accounts, total = await manager.get_accounts(page=1, page_size=100000)
    registered = sum(1 for a in accounts if getattr(a, "registered", False))
    with_kyc = sum(1 for a in accounts if getattr(a, "kyc_level", None))
    with_balance = sum(1 for a in accounts if getattr(a, "balance_usd", 0) > 0)
    groups: Dict[str, int] = {}
    for acc in accounts:
        g = getattr(acc, "group_name", "no_group") or "no_group"
        groups[g] = groups.get(g, 0) + 1
    return {
        "total_accounts": total,
        "registered": registered,
        "with_kyc": with_kyc,
        "with_balance": with_balance,
        "groups": groups,
    }
