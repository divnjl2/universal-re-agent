"""
Captcha router — captcha service management and testing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

logger = logging.getLogger("app.routers.captcha")
router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


class CaptchaTestRequest(BaseModel):
    service: str


class CaptchaBalanceResponse(BaseModel):
    service: str
    balance: float
    enabled: bool = True


@router.get("/services")
async def list_captcha_services(request: Request):
    """List configured captcha services with status."""
    manager = _get_manager(request)
    services = manager.config.captcha_services
    return {
        "services": [
            {
                "service": s["service"],
                "enabled": s.get("enabled", True),
                "priority": s.get("priority", 0),
            }
            for s in services
        ]
    }


@router.get("/balance")
async def get_captcha_balance(request: Request, service: str = Query(...)):
    """Get balance for a captcha service.

    NOTE: Actual balance checking requires the anycaptcha solver to expose
    a balance API. Currently returns the service config status.
    """
    manager = _get_manager(request)
    services = manager.config.captcha_services
    found = None
    for s in services:
        if s["service"] == service:
            found = s
            break
    if not found:
        return CaptchaBalanceResponse(service=service, balance=0.0, enabled=False)
    # TODO: Query actual balance via anycaptcha service API when available
    return CaptchaBalanceResponse(
        service=service,
        balance=-1.0,  # -1 indicates balance not queryable yet
        enabled=found.get("enabled", True),
    )


@router.post("/test")
async def test_captcha(body: CaptchaTestRequest, request: Request):
    """Test captcha solving service.

    NOTE: Full captcha test requires a live PrivateClient with captcha solver.
    This endpoint validates that the service is configured.
    """
    manager = _get_manager(request)
    services = manager.config.captcha_services
    found = any(s["service"] == body.service for s in services)
    if not found:
        return {"service": body.service, "status": "not_configured", "solve_time_ms": 0}
    return {"service": body.service, "status": "configured", "solve_time_ms": 0}
