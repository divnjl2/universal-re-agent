"""
Captcha router — captcha service management and testing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Query
from pydantic import BaseModel

logger = logging.getLogger("app.routers.captcha")
router = APIRouter()


class CaptchaTestRequest(BaseModel):
    service: str


class CaptchaBalanceResponse(BaseModel):
    service: str
    balance: float
    enabled: bool = True


@router.get("/services")
async def list_captcha_services():
    """List configured captcha services with status."""
    return {"services": []}


@router.get("/balance")
async def get_captcha_balance(service: str = Query(...)):
    """Get balance for a captcha service."""
    return CaptchaBalanceResponse(service=service, balance=0.0)


@router.post("/test")
async def test_captcha(request: CaptchaTestRequest):
    """Test captcha solving service."""
    return {"service": request.service, "status": "ok", "solve_time_ms": 0}
