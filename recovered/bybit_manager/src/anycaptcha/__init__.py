"""
Anycaptcha — unified async captcha solving library.

Supports: capmonster, anti-captcha, capsolver, 2captcha, rucaptcha,
azcaptcha, captcha.guru, DeathByCaptcha.

Captcha types: reCAPTCHA v2/v3, GeeTest v3/v4, hCaptcha, FunCaptcha,
image captcha, text captcha.
"""

from .solver import CaptchaSolver
from .errors import AnyCaptchaException, CaptchaError, CaptchaTimeout
from .enums import CaptchaType, CaptchaServiceType

__all__ = [
    "CaptchaSolver",
    "AnyCaptchaException",
    "CaptchaError",
    "CaptchaTimeout",
    "CaptchaType",
    "CaptchaServiceType",
]
