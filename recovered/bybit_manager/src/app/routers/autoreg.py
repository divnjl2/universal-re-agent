"""
Auto-registration router — full flow from email generation to Bybit account.

Flow:
1. Generate iCloud HME alias (or use provided email)
2. Create account record in DB
3. Register on Bybit (captcha → email verify → register)
4. Enable 2FA (optional)
5. Return account details
"""

import asyncio
import logging
import secrets
import string
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.autoreg")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


# ================================================================
# Schemas
# ================================================================

class AutoRegRequest(BaseModel):
    """Request to auto-register one or more Bybit accounts."""
    count: int = Field(1, ge=1, le=50, description="Number of accounts to register")
    group_name: str = "autoreg"
    ref_code: str = ""
    country_code: str = ""
    proxy: Optional[str] = Field(None, description="Proxy string (user:pass@host:port)")
    password: Optional[str] = Field(None, description="Password for all accounts (random if empty)")
    icloud_cookie_file: str = Field("config/icloud_cookies.txt", description="Path to iCloud cookies")
    icloud_cookies: Optional[str] = Field(None, description="Raw iCloud cookie string (overrides file)")
    enable_2fa: bool = False
    use_hme: bool = Field(True, description="Generate iCloud HME emails (False = use provided emails)")
    emails: Optional[List[str]] = Field(None, description="Pre-existing emails (when use_hme=False)")
    imap_address: Optional[str] = None
    imap_password: Optional[str] = None
    label_prefix: str = "bybit"


class AutoRegResult(BaseModel):
    """Result of auto-registration."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)
    emails_generated: List[str] = Field(default_factory=list)


def _generate_password(length: int = 16) -> str:
    """Generate a secure random password meeting Bybit requirements."""
    # Bybit requires: uppercase, lowercase, digit, special char, 8-32 chars
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in pwd) and
            any(c.islower() for c in pwd) and
            any(c.isdigit() for c in pwd) and
            any(c in "!@#$%&*" for c in pwd)):
            return pwd


# ================================================================
# Endpoints
# ================================================================

@router.post("/register", response_model=AutoRegResult)
async def auto_register(body: AutoRegRequest, request: Request):
    """
    Full auto-registration flow:
    1. Generate iCloud HME emails (or use provided)
    2. Create DB records
    3. Register on Bybit
    4. Optionally enable 2FA
    """
    manager = _get_manager(request)
    result = AutoRegResult()

    # Step 1: Get emails
    emails = []
    if body.use_hme:
        from bybit_manager.icloud_hme import HideMyEmailClient

        hme_kwargs = {}
        if body.icloud_cookies:
            hme_kwargs["cookies"] = body.icloud_cookies
        else:
            hme_kwargs["cookie_file"] = body.icloud_cookie_file

        async with HideMyEmailClient(**hme_kwargs) as hme:
            for i in range(body.count):
                email = await hme.generate_one(
                    label=f"{body.label_prefix}-{i+1}"
                )
                if email:
                    emails.append(email)
                    result.emails_generated.append(email)
                else:
                    result.failed.append({
                        "step": "hme_generate",
                        "index": i,
                        "error": "Failed to generate iCloud HME email",
                    })

        if not emails:
            raise HTTPException(
                status_code=502,
                detail="Failed to generate any iCloud HME emails. Check cookies.",
            )
    else:
        if not body.emails or len(body.emails) < body.count:
            raise HTTPException(
                status_code=400,
                detail=f"Need {body.count} emails but got {len(body.emails or [])}",
            )
        emails = body.emails[:body.count]

    # Step 2 + 3: Create DB records and register
    for email in emails:
        password = body.password or _generate_password()
        try:
            # Create in DB
            account = await manager.create_account(
                email_address=email,
                password=password,
                group_name=body.group_name,
                proxy=body.proxy,
                imap_address=body.imap_address,
                imap_password=body.imap_password,
                inviter_ref_code=body.ref_code,
                preferred_country_code=body.country_code,
            )
            db_id = account.database_id

            # Register on Bybit
            try:
                client = await manager.get_client(db_id)
                resp = await client.client.register(
                    ref_code=body.ref_code,
                )
                await manager.update_account(
                    db_id,
                    registered=True,
                    cookies=client.client.export_cookies(),
                )

                account_info = {
                    "database_id": db_id,
                    "email": email,
                    "password": password,
                    "status": "registered",
                }

                # Step 4: Enable 2FA if requested
                if body.enable_2fa:
                    try:
                        secret, uri = await client.client.generate_and_enable_2fa_logic()
                        await manager.update_account(
                            db_id, totp_secret=secret, totp_enabled=True,
                        )
                        account_info["totp_secret"] = secret
                        account_info["status"] = "registered_with_2fa"
                    except Exception as e2fa:
                        logger.warning("2FA enable failed for %s: %s", email, e2fa)
                        account_info["2fa_error"] = str(e2fa)

                result.success.append(account_info)

            except Exception as reg_err:
                logger.error("Bybit registration failed for %s: %s", email, reg_err)
                result.failed.append({
                    "database_id": db_id,
                    "email": email,
                    "password": password,
                    "step": "bybit_register",
                    "error": str(reg_err),
                })

        except Exception as db_err:
            logger.error("DB create failed for %s: %s", email, db_err)
            result.failed.append({
                "email": email,
                "step": "db_create",
                "error": str(db_err),
            })

    return result


@router.post("/register-existing")
async def register_existing_accounts(
    request: Request,
    database_ids: List[int] = [],
    group_name: Optional[str] = None,
    ref_code: str = "",
):
    """Register existing DB accounts on Bybit (skip email generation)."""
    manager = _get_manager(request)
    result = AutoRegResult()

    # Get accounts by IDs or group
    if database_ids:
        ids = database_ids
    elif group_name:
        accounts, _ = await manager.get_accounts(group_name=group_name, page_size=10000)
        ids = [a.database_id for a in accounts if not getattr(a, "registered", False)]
    else:
        raise HTTPException(status_code=400, detail="Provide database_ids or group_name")

    for db_id in ids:
        try:
            client = await manager.get_client(db_id)
            await client.client.register(ref_code=ref_code)
            await manager.update_account(
                db_id,
                registered=True,
                cookies=client.client.export_cookies(),
            )
            result.success.append({"database_id": db_id, "status": "registered"})
        except Exception as e:
            logger.error("Register failed for %d: %s", db_id, e)
            result.failed.append({"database_id": db_id, "error": str(e)})

    return result
