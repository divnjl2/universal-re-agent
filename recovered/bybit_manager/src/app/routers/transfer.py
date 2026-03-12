"""
Transfer router — internal account transfers between sub-accounts.

Handles: fund-to-unified, unified-to-fund, and other internal transfers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.transfer")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class TransferRequest(BaseModel):
    """Internal transfer request."""
    database_ids: List[int]
    coin: str = "USDT"
    amount: float
    from_account_type: str = "FUND"  # FUND, UNIFIED, CONTRACT, SPOT, etc.
    to_account_type: str = "UNIFIED"


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/execute", response_model=BulkOperationResult)
async def execute_transfer(body: TransferRequest, request: Request):
    """Execute internal transfer for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.transfer(
                from_account=body.from_account_type,
                to_account=body.to_account_type,
                coin=body.coin,
                amount=body.amount,
            )
            results.success.append({
                "database_id": db_id,
                "coin": body.coin,
                "amount": body.amount,
                "from": body.from_account_type,
                "to": body.to_account_type,
                "status": "transferred",
            })
        except Exception as e:
            logger.error("Transfer failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/account-types")
async def get_account_types():
    """Get available account types for transfer."""
    return {
        "account_types": [
            "FUND", "UNIFIED", "CONTRACT", "SPOT",
            "COPY_TRADE", "INVESTMENT", "LAUNCHPOOL",
            "BOT", "MT5", "OPTION",
        ]
    }


@router.get("/balance/{database_id}")
async def get_transfer_balance(
    database_id: int,
    request: Request,
    coin: str = Query("USDT"),
    account_type: str = Query("FUND"),
):
    """Get available balance for transfer from a sub-account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_finance_account_balance(
            account_type=account_type,
        )
        result = resp.result if hasattr(resp, "result") else {}
        balance = 0.0
        if isinstance(result, dict):
            balance = float(result.get("balance", 0.0))
        elif isinstance(result, list):
            # Find the matching coin in the list
            for item in result:
                if isinstance(item, dict) and item.get("coin", "").upper() == coin.upper():
                    balance = float(item.get("balance", 0.0))
                    break
        return {
            "database_id": database_id,
            "coin": coin,
            "account_type": account_type,
            "available": balance,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
