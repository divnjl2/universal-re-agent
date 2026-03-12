"""
Bybit captcha models — recovered from memory dump.

Captcha services found in memory:
- capmonster.cloud (createTask/getTaskResult)
- anti-captcha.com
- capsolver.com
- 2captcha.com / rucaptcha.com
- azcaptcha.com
- sctg.xyz (captcha.guru)
- dbcapi.me (DeathByCaptcha)

Tencent captcha URLs:
- global.captcha.gtimg.com
- sg.captcha.qcloud.com
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CaptchaService(str, Enum):
    """Supported captcha solving services."""
    CAPMONSTER = "capmonster"
    ANTI_CAPTCHA = "anti_captcha"
    CAPSOLVER = "capsolver"
    TWO_CAPTCHA = "2captcha"
    RUCAPTCHA = "rucaptcha"
    AZCAPTCHA = "azcaptcha"
    CAPTCHA_GURU = "captcha_guru"
    DEATHBYCAPTCHA = "deathbycaptcha"
    SCTG = "sctg"


CAPTCHA_SERVICES: Dict[str, str] = {
    "capmonster": "https://api.capmonster.cloud",
    "anti_captcha": "https://api.anti-captcha.com",
    "capsolver": "https://api.capsolver.com",
    "2captcha": "https://2captcha.com",
    "rucaptcha": "https://rucaptcha.com",
    "azcaptcha": "http://azcaptcha.com",
    "captcha_guru": "http://api.sctg.xyz",
    "deathbycaptcha": "http://api.dbcapi.me/api",
}

CAPTCHA_SERVICES_JSON = CAPTCHA_SERVICES  # alias


class CaptchaOrder(BaseModel):
    """Captcha order response from Bybit."""
    captcha_type: str = "recaptcha"  # recaptcha, geetest, geetest_v4
    serial_no: str = ""
    scene: str = "31000"
    site_key: str = ""
    page_url: str = ""
    gt: str = ""  # GeeTest GT
    challenge: str = ""  # GeeTest challenge
    captcha_id: str = ""  # GeeTest v4 captcha_id


class CaptchaVerifyRequest(BaseModel):
    """Request body for captcha verification."""
    captcha_type: str = "recaptcha"
    scene: str = "31000"
    serial_no: str = ""
    g_recaptcha_response: str = ""
    captcha_output: str = ""  # GeeTest v4
    gen_time: str = ""
    lot_number: str = ""
    pass_token: str = ""


class BaseCaptchaSolution(BaseModel):
    """Base captcha solution."""
    solution: Dict[str, Any] = Field(default_factory=dict)


class TencentCaptchaSolution(BaseCaptchaSolution):
    """Tencent captcha solution (used by Bybit for Tencent CAPTCHA)."""
    ticket: str = ""
    rand_str: str = ""
    app_id: str = ""


class BadTencentCaptchaSolution(Exception):
    """Raised when Tencent captcha solution is invalid."""
    pass


class BadTencentCaptchaCookies(Exception):
    """Raised when Tencent captcha cookies are missing/invalid."""
    pass


class AnyCaptchaException(Exception):
    """General captcha solving exception."""
    pass


class CaptchaServiceConfig(BaseModel):
    """Configuration for a captcha service."""
    service: str = "capmonster"
    api_key: str = ""
    priority: int = 0
    enabled: bool = True

    class Config:
        extra = "allow"
