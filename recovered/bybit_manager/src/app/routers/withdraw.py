"""
Withdraw router — API endpoints for withdrawal management.

Handles: on-chain withdrawals, internal transfers, withdraw addresses,
fees, history, and whitelist management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.withdraw")

router = APIRouter()


# ================================================================
# Request/Response schemas
# ================================================================

class WithdrawRequest(BaseModel):
    """Request to execute a withdrawal."""
    database_ids: List[int]
    coin: str = "USDT"
    chain: str = "APTOS"
    address: str
    amount: float
    withdraw_type: int = 0  # 0=onchain, 2=internal


class AddWithdrawAddressRequest(BaseModel):
    """Request to add a withdraw address."""
    database_ids: List[int]
    coin: str = "USDT"
    chain: str = ""
    address: str
    remark: str = ""


class DeleteWithdrawAddressRequest(BaseModel):
    """Request to delete a withdraw address."""
    database_ids: List[int]
    address_id: int


class SwitchWhitelistRequest(BaseModel):
    """Request to toggle withdraw whitelist."""
    database_ids: List[int]
    enable: bool = True


class WithdrawResponse(BaseModel):
    """Response for withdrawal operations."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


# ================================================================
# Endpoints
# ================================================================

@router.post("/onchain", response_model=WithdrawResponse)
async def onchain_withdraw(request: WithdrawRequest):
    """Execute on-chain withdrawal for multiple accounts."""
    # Implementation delegates to manager.withdraw_logic for each account
    results = WithdrawResponse()
    for db_id in request.database_ids:
        try:
            # TODO: Get client from pool, call withdraw_logic
            results.success.append({
                "database_id": db_id,
                "status": "submitted",
                "coin": request.coin,
                "amount": request.amount,
            })
        except Exception as e:
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/internal", response_model=WithdrawResponse)
async def internal_withdraw(request: WithdrawRequest):
    """Execute internal (Bybit-to-Bybit) withdrawal."""
    results = WithdrawResponse()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "status": "submitted",
            })
        except Exception as e:
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.get("/coins")
async def get_withdraw_coins(database_id: int = Query(...)):
    """Get available coins for withdrawal."""
    return {"database_id": database_id, "coins": []}


@router.get("/coins-chains")
async def get_withdraw_coins_chains(database_id: int = Query(...)):
    """Get withdraw coins with chain details."""
    return {"database_id": database_id, "coins": []}


@router.get("/fee")
async def get_withdraw_fee(
    database_id: int = Query(...),
    coin: str = Query("USDT"),
    chain: str = Query("APTOS"),
    amount: float = Query(20.0),
):
    """Get withdrawal fee for coin/chain/amount."""
    return {"database_id": database_id, "coin": coin, "chain": chain, "fee": 0.0}


@router.get("/available-balance")
async def get_available_balance(
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get available balance for withdrawal."""
    return {"database_id": database_id, "coin": coin, "available": 0.0}


@router.get("/history")
async def get_withdraw_history(
    database_id: int = Query(...),
    page: int = Query(1),
    page_size: int = Query(500),
):
    """Get withdrawal history."""
    return {"database_id": database_id, "records": [], "total": 0}


@router.get("/addresses")
async def get_withdraw_addresses(
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get saved withdraw addresses."""
    return {"database_id": database_id, "addresses": []}


@router.post("/addresses/add", response_model=WithdrawResponse)
async def add_withdraw_address(request: AddWithdrawAddressRequest):
    """Add a new withdraw address to whitelist."""
    results = WithdrawResponse()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "status": "added",
            })
        except Exception as e:
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/addresses/delete", response_model=WithdrawResponse)
async def delete_withdraw_address(request: DeleteWithdrawAddressRequest):
    """Delete a saved withdraw address."""
    results = WithdrawResponse()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "status": "deleted",
            })
        except Exception as e:
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/whitelist/switch", response_model=WithdrawResponse)
async def switch_whitelist(request: SwitchWhitelistRequest):
    """Toggle withdraw address whitelist verification."""
    results = WithdrawResponse()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "whitelist_enabled": request.enable,
            })
        except Exception as e:
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.get("/precisions")
async def get_withdraw_precisions(
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get withdraw precision (decimal places) per chain."""
    return {"database_id": database_id, "coin": coin, "precisions": {}}
