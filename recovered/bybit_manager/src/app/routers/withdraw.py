"""
Withdraw router — API endpoints for withdrawal management.

Handles: on-chain withdrawals, internal transfers, withdraw addresses,
fees, history, and whitelist management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.withdraw")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
async def onchain_withdraw(body: WithdrawRequest, request: Request):
    """Execute on-chain withdrawal for multiple accounts."""
    manager = _get_manager(request)
    results = await manager.bulk_withdraw(
        database_ids=body.database_ids,
        coin=body.coin,
        chain=body.chain,
        address=body.address,
        amount=body.amount,
        withdraw_type=0,
    )
    return WithdrawResponse(**results)


@router.post("/internal", response_model=WithdrawResponse)
async def internal_withdraw(body: WithdrawRequest, request: Request):
    """Execute internal (Bybit-to-Bybit) withdrawal."""
    manager = _get_manager(request)
    results = WithdrawResponse()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.internal_withdraw(
                coin=body.coin,
                address=body.address,
                amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "status": "submitted",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Internal withdraw failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.get("/coins")
async def get_withdraw_coins(request: Request, database_id: int = Query(...)):
    """Get available coins for withdrawal."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_withdraw_coins()
        return {"database_id": database_id, "coins": resp.result or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/coins-chains")
async def get_withdraw_coins_chains(request: Request, database_id: int = Query(...)):
    """Get withdraw coins with chain details."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_withdraw_coins_with_chains()
        return {"database_id": database_id, "coins": resp.result or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/fee")
async def get_withdraw_fee(
    request: Request,
    database_id: int = Query(...),
    coin: str = Query("USDT"),
    chain: str = Query("APTOS"),
    amount: float = Query(20.0),
):
    """Get withdrawal fee for coin/chain/amount."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_withdraw_fee(
            coin=coin, chain=chain, amount=amount,
        )
        return {
            "database_id": database_id,
            "coin": coin,
            "chain": chain,
            "fee": resp.result if hasattr(resp, "result") else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/available-balance")
async def get_available_balance(
    request: Request,
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get available balance for withdrawal."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_available_withdraw_balance(coin=coin)
        result = resp.result if hasattr(resp, "result") else {}
        available = result.get("available", 0.0) if isinstance(result, dict) else 0.0
        return {"database_id": database_id, "coin": coin, "available": available}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_withdraw_history(
    request: Request,
    database_id: int = Query(...),
    page: int = Query(1),
    page_size: int = Query(500),
):
    """Get withdrawal history."""
    manager = _get_manager(request)
    try:
        # Also sync history to DB
        count = await manager.sync_withdraw_history(database_id)
        client = await manager.get_client(database_id)
        resp = await client.client.get_withdraw_history(
            page=page, page_size=page_size,
        )
        result = resp.result if hasattr(resp, "result") else {}
        records = result.get("records", []) if isinstance(result, dict) else []
        total = result.get("total", len(records)) if isinstance(result, dict) else 0
        return {"database_id": database_id, "records": records, "total": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/addresses")
async def get_withdraw_addresses(
    request: Request,
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get saved withdraw addresses."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_withdraw_addresses(coin=coin)
        return {
            "database_id": database_id,
            "addresses": resp.result or [],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/addresses/add", response_model=WithdrawResponse)
async def add_withdraw_address(body: AddWithdrawAddressRequest, request: Request):
    """Add a new withdraw address to whitelist."""
    manager = _get_manager(request)
    results = WithdrawResponse()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.add_withdraw_address_logic(
                coin=body.coin,
                chain=body.chain,
                address=body.address,
                remark=body.remark,
            )
            results.success.append({
                "database_id": db_id,
                "status": "added",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Add address failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/addresses/delete", response_model=WithdrawResponse)
async def delete_withdraw_address(body: DeleteWithdrawAddressRequest, request: Request):
    """Delete a saved withdraw address."""
    manager = _get_manager(request)
    results = WithdrawResponse()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.delete_withdraw_address(body.address_id)
            results.success.append({
                "database_id": db_id,
                "status": "deleted",
            })
        except Exception as e:
            logger.error("Delete address failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.post("/whitelist/switch", response_model=WithdrawResponse)
async def switch_whitelist(body: SwitchWhitelistRequest, request: Request):
    """Toggle withdraw address whitelist verification."""
    manager = _get_manager(request)
    results = WithdrawResponse()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.switch_withdraw_address_verification(
                enable=body.enable,
            )
            results.success.append({
                "database_id": db_id,
                "whitelist_enabled": body.enable,
            })
        except Exception as e:
            logger.error("Whitelist switch failed for %d: %s", db_id, e)
            results.failed.append({
                "database_id": db_id,
                "error": str(e),
            })
    return results


@router.get("/precisions")
async def get_withdraw_precisions(
    request: Request,
    database_id: int = Query(...),
    coin: str = Query("USDT"),
):
    """Get withdraw precision (decimal places) per chain."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        precisions = await client.client.get_withdraw_precisions(coin=coin)
        return {"database_id": database_id, "coin": coin, "precisions": precisions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
