"""
Browser profile management — AdsPower integration.

Handles creating, opening, closing, and deleting AdsPower browser profiles
linked to Bybit accounts.
"""

from __future__ import annotations

import enum
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from pydantic import BaseModel, Field

from bybit_manager.config import Config, ADSPOWER_API_URL
from bybit_manager.manager import Manager

logger = logging.getLogger("bybit_manager.scripts.browser")


class BrowserActionType(str, enum.Enum):
    """Supported browser actions."""
    CREATE_PROFILE = "create_profile"
    OPEN_PROFILE = "open_profile"
    CLOSE_PROFILE = "close_profile"
    DELETE_PROFILE = "delete_profile"
    CHECK_STATUS = "check_status"


class BrowserRequest(BaseModel):
    """Request schema for browser actions."""
    action: BrowserActionType
    database_ids: List[int] = Field(default_factory=list)
    group_name: Optional[str] = None


class BrowserResponse(BaseModel):
    """Response schema for browser actions."""
    action: str
    total: int = 0
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


async def _adspower_request(
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    api_url: str = ADSPOWER_API_URL,
) -> Dict[str, Any]:
    """Make a request to the AdsPower local API."""
    url = f"{api_url}{path}"
    async with aiohttp.ClientSession() as session:
        async with session.request(
            method, url, params=params, json=json_data,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            data = await resp.json()
            if data.get("code") != 0:
                raise RuntimeError(
                    f"AdsPower error: {data.get('msg', 'unknown')} (code={data.get('code')})"
                )
            return data.get("data", {})


async def _create_profile(
    account_email: str,
    proxy: Optional[str] = None,
) -> str:
    """Create an AdsPower browser profile. Returns profile_id."""
    body: Dict[str, Any] = {
        "name": account_email,
        "group_id": "0",
        "remark": f"bybit_{account_email}",
    }
    if proxy:
        # Parse proxy for AdsPower format
        body["user_proxy_config"] = {
            "proxy_soft": "other",
            "proxy_type": "http",
            "proxy_host": proxy,
        }

    data = await _adspower_request("POST", "/api/v1/user/create", json_data=body)
    profile_id = data.get("id", "")
    logger.info("Created AdsPower profile %s for %s", profile_id, account_email)
    return profile_id


async def _open_profile(profile_id: str) -> Dict[str, Any]:
    """Open an AdsPower browser profile. Returns connection info."""
    data = await _adspower_request(
        "GET", "/api/v1/browser/start",
        params={"user_id": profile_id},
    )
    return {
        "profile_id": profile_id,
        "ws_endpoint": data.get("ws", {}).get("puppeteer", ""),
        "debug_port": data.get("debug_port", ""),
    }


async def _close_profile(profile_id: str) -> None:
    """Close an AdsPower browser profile."""
    await _adspower_request(
        "GET", "/api/v1/browser/stop",
        params={"user_id": profile_id},
    )
    logger.info("Closed AdsPower profile %s", profile_id)


async def _delete_profile(profile_id: str) -> None:
    """Delete an AdsPower browser profile."""
    await _adspower_request(
        "POST", "/api/v1/user/delete",
        json_data={"user_ids": [profile_id]},
    )
    logger.info("Deleted AdsPower profile %s", profile_id)


async def _check_status(profile_id: str) -> Dict[str, Any]:
    """Check AdsPower browser profile status."""
    data = await _adspower_request(
        "GET", "/api/v1/browser/active",
        params={"user_id": profile_id},
    )
    return {"profile_id": profile_id, "status": data.get("status", "unknown")}


async def run_browser_action(
    manager: Manager,
    request: BrowserRequest,
) -> BrowserResponse:
    """Execute a browser management action across accounts."""
    db_ids = request.database_ids

    # Resolve group to database_ids if needed
    if not db_ids and request.group_name:
        accounts, _ = await manager.get_accounts(
            group_name=request.group_name,
            page=1,
            page_size=10000,
        )
        db_ids = [a.database_id for a in accounts]

    if not db_ids:
        return BrowserResponse(action=request.action.value, total=0)

    response = BrowserResponse(action=request.action.value, total=len(db_ids))

    for db_id in db_ids:
        try:
            account = await manager.get_account(db_id)
            if not account:
                response.failed.append({"database_id": db_id, "error": "Account not found"})
                continue

            action = request.action

            if action == BrowserActionType.CREATE_PROFILE:
                profile_id = await _create_profile(
                    account.email_address, account.proxy,
                )
                await manager.update_account(db_id, adspower_profile_id=profile_id)
                response.success.append({
                    "database_id": db_id,
                    "profile_id": profile_id,
                })

            elif action == BrowserActionType.OPEN_PROFILE:
                if not account.adspower_profile_id:
                    response.failed.append({
                        "database_id": db_id,
                        "error": "No AdsPower profile_id",
                    })
                    continue
                info = await _open_profile(account.adspower_profile_id)
                response.success.append({"database_id": db_id, **info})

            elif action == BrowserActionType.CLOSE_PROFILE:
                if not account.adspower_profile_id:
                    response.failed.append({
                        "database_id": db_id,
                        "error": "No AdsPower profile_id",
                    })
                    continue
                await _close_profile(account.adspower_profile_id)
                response.success.append({"database_id": db_id, "status": "closed"})

            elif action == BrowserActionType.DELETE_PROFILE:
                if not account.adspower_profile_id:
                    response.failed.append({
                        "database_id": db_id,
                        "error": "No AdsPower profile_id",
                    })
                    continue
                await _delete_profile(account.adspower_profile_id)
                await manager.update_account(db_id, adspower_profile_id=None)
                response.success.append({"database_id": db_id, "status": "deleted"})

            elif action == BrowserActionType.CHECK_STATUS:
                if not account.adspower_profile_id:
                    response.failed.append({
                        "database_id": db_id,
                        "error": "No AdsPower profile_id",
                    })
                    continue
                info = await _check_status(account.adspower_profile_id)
                response.success.append({"database_id": db_id, **info})

        except Exception as e:
            logger.error("Browser action failed for %d: %s", db_id, e)
            response.failed.append({"database_id": db_id, "error": str(e)})

    return response
