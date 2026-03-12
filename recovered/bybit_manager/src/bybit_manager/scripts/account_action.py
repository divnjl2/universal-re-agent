"""
Batch account actions — login, register, check balance, withdraw, get profile, etc.

Each action is dispatched via run_account_action() which calls the appropriate
Manager bulk method.
"""

from __future__ import annotations

import asyncio
import enum
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from bybit_manager.config import Config
from bybit_manager.manager import Manager

logger = logging.getLogger("bybit_manager.scripts.account_action")


class AccountActionType(str, enum.Enum):
    """Supported batch account actions."""
    LOGIN = "login"
    REGISTER = "register"
    CHECK_BALANCE = "check_balance"
    GET_PROFILE = "get_profile"
    WITHDRAW = "withdraw"
    SYNC_FINANCE = "sync_finance"
    SYNC_DEPOSIT_HISTORY = "sync_deposit_history"
    SYNC_WITHDRAW_HISTORY = "sync_withdraw_history"


class AccountActionRequest(BaseModel):
    """Request schema for batch account actions."""
    action: AccountActionType
    database_ids: List[int] = Field(default_factory=list)
    group_name: Optional[str] = None
    concurrency: int = Field(default=5, ge=1, le=50)
    # Withdraw-specific fields
    coin: Optional[str] = None
    chain: Optional[str] = None
    address: Optional[str] = None
    amount: Optional[float] = None


class AccountActionResponse(BaseModel):
    """Response schema for batch account actions."""
    action: str
    total: int = 0
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


async def run_account_action(
    manager: Manager,
    request: AccountActionRequest,
) -> AccountActionResponse:
    """Execute a batch account action.

    If database_ids is empty but group_name is set, fetches all accounts
    in that group first.
    """
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
        return AccountActionResponse(action=request.action.value, total=0)

    logger.info(
        "Running %s on %d accounts (concurrency=%d)",
        request.action.value, len(db_ids), request.concurrency,
    )

    action = request.action
    result: Dict[str, List[Dict[str, Any]]]

    if action == AccountActionType.LOGIN:
        result = await manager.bulk_login(db_ids, concurrency=request.concurrency)

    elif action == AccountActionType.CHECK_BALANCE:
        result = await manager.bulk_check_balance(db_ids, concurrency=request.concurrency)

    elif action == AccountActionType.GET_PROFILE:
        result = await manager.bulk_get_profile(db_ids, concurrency=request.concurrency)

    elif action == AccountActionType.WITHDRAW:
        if not all([request.coin, request.chain, request.address, request.amount]):
            return AccountActionResponse(
                action=action.value,
                total=len(db_ids),
                failed=[{"error": "coin, chain, address, amount are required for withdraw"}],
            )
        result = await manager.bulk_withdraw(
            db_ids,
            coin=request.coin,
            chain=request.chain,
            address=request.address,
            amount=request.amount,
            concurrency=request.concurrency,
        )

    elif action == AccountActionType.SYNC_FINANCE:
        result = await _bulk_sync(
            manager, db_ids, manager.sync_finance_accounts, request.concurrency,
        )

    elif action == AccountActionType.SYNC_DEPOSIT_HISTORY:
        result = await _bulk_sync(
            manager, db_ids, manager.sync_deposit_history, request.concurrency,
        )

    elif action == AccountActionType.SYNC_WITHDRAW_HISTORY:
        result = await _bulk_sync(
            manager, db_ids, manager.sync_withdraw_history, request.concurrency,
        )

    elif action == AccountActionType.REGISTER:
        # Register uses login flow (creates account on Bybit side)
        result = await manager.bulk_login(db_ids, concurrency=request.concurrency)

    else:
        return AccountActionResponse(
            action=action.value,
            total=len(db_ids),
            failed=[{"error": f"Unknown action: {action.value}"}],
        )

    return AccountActionResponse(
        action=action.value,
        total=len(db_ids),
        success=result.get("success", []),
        failed=result.get("failed", []),
    )


async def _bulk_sync(
    manager: Manager,
    database_ids: List[int],
    sync_fn,
    concurrency: int,
) -> Dict[str, List[Dict[str, Any]]]:
    """Generic bulk sync helper for single-account sync methods."""
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, List[Dict[str, Any]]] = {"success": [], "failed": []}

    async def _do_one(db_id: int):
        async with sem:
            try:
                res = await sync_fn(db_id)
                results["success"].append({
                    "database_id": db_id,
                    "result": res,
                })
            except Exception as e:
                logger.error("Sync failed for %d: %s", db_id, e)
                results["failed"].append({
                    "database_id": db_id,
                    "error": str(e),
                })

    await asyncio.gather(*[_do_one(db_id) for db_id in database_ids])
    return results
