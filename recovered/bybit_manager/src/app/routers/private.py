"""
Private router — endpoints for authenticated Bybit operations.

Handles: login, profile, 2FA, password, registration, verification flows.
These endpoints require account credentials and interact with Bybit's private API.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.private")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


# ================================================================
# Request/Response schemas
# ================================================================

class LoginRequest(BaseModel):
    """Login request for multiple accounts."""
    database_ids: List[int]
    concurrency: int = 5


class RegisterRequest(BaseModel):
    """Register new Bybit accounts."""
    database_ids: List[int]
    ref_code: str = ""
    country_code: str = ""


class ProfileRequest(BaseModel):
    """Fetch profile for accounts."""
    database_ids: List[int]


class Enable2FARequest(BaseModel):
    """Enable Google 2FA on accounts."""
    database_ids: List[int]


class Disable2FARequest(BaseModel):
    """Disable Google 2FA on accounts."""
    database_ids: List[int]


class ChangePasswordRequest(BaseModel):
    """Change password on accounts."""
    database_ids: List[int]
    new_password: str


class VerifyEmailRequest(BaseModel):
    """Verify email on accounts."""
    database_ids: List[int]


class BulkOperationResult(BaseModel):
    """Result of operations across multiple accounts."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


# ================================================================
# Endpoints
# ================================================================

@router.post("/login", response_model=BulkOperationResult)
async def login(body: LoginRequest, request: Request):
    """Login multiple accounts (with auto captcha + 2FA handling)."""
    manager = _get_manager(request)
    results = await manager.bulk_login(
        database_ids=body.database_ids,
        concurrency=body.concurrency,
    )
    return BulkOperationResult(**results)


@router.post("/register", response_model=BulkOperationResult)
async def register(body: RegisterRequest, request: Request):
    """Register new Bybit accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.register(
                ref_code=body.ref_code,
            )
            await manager.update_account(db_id, registered=True, cookies=client.cookies)
            results.success.append({
                "database_id": db_id,
                "status": "registered",
            })
        except Exception as e:
            logger.error("Register failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/profile", response_model=BulkOperationResult)
async def get_profiles(body: ProfileRequest, request: Request):
    """Fetch and update profile info for accounts."""
    manager = _get_manager(request)
    results = await manager.bulk_get_profile(database_ids=body.database_ids)
    return BulkOperationResult(**results)


@router.get("/profile/{database_id}")
async def get_single_profile(database_id: int, request: Request):
    """Get profile for a single account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_profile()
        profile = resp.result if resp.result else {}
        return {"database_id": database_id, "profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enable-2fa", response_model=BulkOperationResult)
async def enable_2fa(body: Enable2FARequest, request: Request):
    """Enable Google 2FA on accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            secret, uri = await client.client.generate_and_enable_2fa_logic()
            await manager.update_account(db_id, totp_secret=secret, totp_enabled=True)
            results.success.append({
                "database_id": db_id,
                "status": "2fa_enabled",
                "totp_secret": secret,
            })
        except Exception as e:
            logger.error("Enable 2FA failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/disable-2fa", response_model=BulkOperationResult)
async def disable_2fa(body: Disable2FARequest, request: Request):
    """Disable Google 2FA on accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            await client.client.disable_unknown_2fa_logic()
            await manager.update_account(db_id, totp_enabled=False)
            results.success.append({
                "database_id": db_id,
                "status": "2fa_disabled",
            })
        except Exception as e:
            logger.error("Disable 2FA failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/change-password", response_model=BulkOperationResult)
async def change_password(body: ChangePasswordRequest, request: Request):
    """Change password on accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            await client.client.reset_password_logic(new_password=body.new_password)
            await manager.update_account(db_id, password=body.new_password)
            results.success.append({
                "database_id": db_id,
                "status": "password_changed",
            })
        except Exception as e:
            logger.error("Change password failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/verify-email", response_model=BulkOperationResult)
async def verify_email(body: VerifyEmailRequest, request: Request):
    """Verify email on accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            await client.client.send_email_code_to_register()
            results.success.append({
                "database_id": db_id,
                "status": "email_sent",
            })
        except Exception as e:
            logger.error("Verify email failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.get("/balance/{database_id}")
async def get_balance(database_id: int, request: Request):
    """Get total USD balance for a single account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        balance = await client.client.get_total_usd_balance()
        await manager.update_account(database_id, balance_usd=balance)
        return {"database_id": database_id, "balance_usd": balance}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check-balance", response_model=BulkOperationResult)
async def check_balance(body: ProfileRequest, request: Request):
    """Check balance for multiple accounts."""
    manager = _get_manager(request)
    results = await manager.bulk_check_balance(database_ids=body.database_ids)
    return BulkOperationResult(**results)


@router.get("/referral/{database_id}")
async def get_referral_code(database_id: int, request: Request):
    """Get referral code for an account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        ref_code = await client.client.get_referral_code()
        return {"database_id": database_id, "ref_code": ref_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/finance-accounts/{database_id}")
async def get_finance_accounts(database_id: int, request: Request):
    """Get all sub-account balances."""
    manager = _get_manager(request)
    try:
        records = await manager.sync_finance_accounts(database_id)
        return {"database_id": database_id, "accounts": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
