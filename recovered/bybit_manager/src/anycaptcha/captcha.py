"""
anycaptcha.captcha — compatibility shim.

This module re-exports from the captcha sub-package so that
``from anycaptcha.captcha import RecaptchaV2`` keeps working
regardless of whether the caller imports the module or the package.
"""

from .captcha.base import BaseCaptcha, BaseCaptchaSolution
from .captcha.recaptcha_v2 import RecaptchaV2, RecaptchaV2Solution
from .captcha.geetest import GeeTest, GeeTestSolution
from .captcha.geetest_v4 import GeeTestV4, GeeTestV4Solution
from .enums import CaptchaAlphabet, CaptchaCharType
from .errors import AnyCaptchaException, CaptchaError
