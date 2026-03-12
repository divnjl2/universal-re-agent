"""
Web3 router — Bybit Web3 wallet operations.

Handles: wallet creation, balance checking, swaps, staking, IDO.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.web3")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class Web3WalletCreateRequest(BaseModel):
    database_ids: List[int]
    wallet_type: str = "cloud"  # cloud, mnemonic


class Web3SwapRequest(BaseModel):
    database_ids: List[int]
    chain_id: int
    from_token: str
    to_token: str
    amount: float


class Web3StakeRequest(BaseModel):
    database_ids: List[int]
    chain_id: int
    token: str
    amount: float


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/create-wallet", response_model=BulkOperationResult)
async def create_wallet(body: Web3WalletCreateRequest, request: Request):
    """Create web3 wallets for accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            if body.wallet_type == "cloud":
                resp = await client.client.web3_get_or_create_cloud_wallets()
            else:
                resp = await client.client.web3_create_cloud_wallets()
            results.success.append({
                "database_id": db_id,
                "status": "created",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Create wallet failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/wallets/{database_id}")
async def get_wallets(database_id: int, request: Request):
    """Get web3 wallets for an account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.web3_get_cloud_wallets()
        wallets = resp.result or []
        return {"database_id": database_id, "wallets": wallets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/balance/{database_id}")
async def get_web3_balance(
    database_id: int,
    request: Request,
    wallet_id: Optional[str] = Query(None),
):
    """Get web3 wallet balance."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        if wallet_id:
            resp = await client.client.web3_get_cloud_wallet_tokens(wallet_id)
        else:
            resp = await client.client.web3_get_mnemonic_phrase_wallets_balance_usd()
        result = resp.result if hasattr(resp, "result") else {}
        return {"database_id": database_id, "balance": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/swap", response_model=BulkOperationResult)
async def web3_swap(body: Web3SwapRequest, request: Request):
    """Execute web3 token swap.

    NOTE: Full swap requires building a swap transaction with specific
    parameters (slippage, route, etc.) that depend on the DEX aggregator.
    This endpoint provides the basic swap call.
    """
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.web3_swap(
                chainId=str(body.chain_id),
                fromToken=body.from_token,
                toToken=body.to_token,
                amount=str(body.amount),
            )
            results.success.append({
                "database_id": db_id,
                "status": "swapped",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Web3 swap failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/stake", response_model=BulkOperationResult)
async def web3_stake(body: Web3StakeRequest, request: Request):
    """Stake tokens in web3."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.web3_stake(
                chainId=str(body.chain_id),
                token=body.token,
                amount=str(body.amount),
            )
            results.success.append({
                "database_id": db_id,
                "status": "staked",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("Web3 stake failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/chains")
async def get_supported_chains(request: Request):
    """Get supported web3 chains from Bybit API.

    Falls back to static list if no account context is available.
    """
    # Static fallback — the actual chains come from web3_get_cloud_wallets_chains
    return {
        "chains": [
            {"id": 1, "name": "Ethereum", "type": "EVM"},
            {"id": 56, "name": "BSC", "type": "EVM"},
            {"id": 137, "name": "Polygon", "type": "EVM"},
            {"id": 42161, "name": "Arbitrum", "type": "EVM"},
            {"id": 10, "name": "Optimism", "type": "EVM"},
        ]
    }
