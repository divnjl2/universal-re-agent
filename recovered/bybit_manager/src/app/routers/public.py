"""
Public router — market data and public API endpoints (no auth required).

Handles: instruments, market data, countries, public campaign info.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Query

logger = logging.getLogger("app.routers.public")

router = APIRouter()


@router.get("/instruments")
async def get_instruments(
    category: str = Query("spot", description="spot, linear, inverse, option"),
):
    """Get trading instruments list."""
    return {"category": category, "instruments": []}


@router.get("/market/tickers")
async def get_tickers(
    category: str = Query("spot"),
    symbol: Optional[str] = Query(None),
):
    """Get market tickers."""
    return {"category": category, "tickers": []}


@router.get("/market/kline")
async def get_kline(
    symbol: str = Query(...),
    interval: str = Query("1h"),
    limit: int = Query(200),
):
    """Get kline/candlestick data."""
    return {"symbol": symbol, "interval": interval, "klines": []}


@router.get("/market/orderbook")
async def get_orderbook(
    symbol: str = Query(...),
    limit: int = Query(50),
):
    """Get order book."""
    return {"symbol": symbol, "bids": [], "asks": []}


@router.get("/countries")
async def get_countries():
    """Get supported countries list."""
    return {"countries": []}


@router.get("/permissions")
async def get_country_permissions(
    country_code: str = Query(...),
):
    """Get trading permissions for a country."""
    return {"country_code": country_code, "permissions": {}}


@router.get("/tokensplash/list")
async def get_tokensplash_list():
    """Get active token splash campaigns."""
    return {"campaigns": []}


@router.get("/puzzlehunt/list")
async def get_puzzlehunt_list():
    """Get active puzzle hunt campaigns."""
    return {"campaigns": []}


@router.get("/launchpool/list")
async def get_launchpool_list():
    """Get active launchpool projects."""
    return {"projects": []}


@router.get("/launchpad/list")
async def get_launchpad_list():
    """Get active launchpad (IDO) projects."""
    return {"projects": []}


@router.get("/earn/products")
async def get_earn_products(
    coin: str = Query("USDT"),
):
    """Get earn/savings product list."""
    return {"coin": coin, "products": []}
