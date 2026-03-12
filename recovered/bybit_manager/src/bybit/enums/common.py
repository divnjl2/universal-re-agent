"""
Common Bybit enums — shared across multiple modules.
"""

from __future__ import annotations

from ._base import BybitEnum


class OrderSide(BybitEnum):
    BUY = "Buy"
    SELL = "Sell"


class OrderType(BybitEnum):
    MARKET = "Market"
    LIMIT = "Limit"


class TimeInForce(BybitEnum):
    GTC = "GTC"  # Good Till Cancel
    IOC = "IOC"  # Immediate or Cancel
    FOK = "FOK"  # Fill or Kill
    POST_ONLY = "PostOnly"


class Category(BybitEnum):
    SPOT = "spot"
    LINEAR = "linear"
    INVERSE = "inverse"
    OPTION = "option"


class AccountType(BybitEnum):
    FUND = "FUND"
    UNIFIED = "UNIFIED"
    CONTRACT = "CONTRACT"
    SPOT = "SPOT"


class WithdrawType(BybitEnum):
    ON_CHAIN = "0"
    INTERNAL = "2"


class CaptchaType(BybitEnum):
    RECAPTCHA = "recaptcha"
    GEETEST = "geetest"
    GEETEST_V4 = "geetest_v4"
    TENCENT = "tencent"


class RiskComponentType(BybitEnum):
    GOOGLE2FA = "google2fa"
    EMAIL = "email"
    SMS = "sms"
    CAPTCHA = "captcha"


class ProxyProvider(BybitEnum):
    IPROYAL = "iproyal"
    DATAIMPULSE = "dataimpulse"
    NODEMAVEN = "nodemaven"
