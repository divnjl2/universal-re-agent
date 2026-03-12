"""
anycaptcha.captcha — captcha task definitions.
"""
from .base import BaseCaptcha, BaseCaptchaSolution
from .recaptcha_v2 import RecaptchaV2, RecaptchaV2Solution
from .geetest import GeeTest, GeeTestSolution
from .geetest_v4 import GeeTestV4, GeeTestV4Solution

__all__ = [
    "BaseCaptcha",
    "BaseCaptchaSolution",
    "RecaptchaV2",
    "RecaptchaV2Solution",
    "GeeTest",
    "GeeTestSolution",
    "GeeTestV4",
    "GeeTestV4Solution",
]
