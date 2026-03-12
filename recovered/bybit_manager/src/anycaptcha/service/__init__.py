"""
Captcha solving service implementations.
"""

from .base import BaseService
from .capmonster import CapMonsterService
from .twocaptcha import TwoCaptchaService
from .anti_captcha import AntiCaptchaService
from .capsolver import CapsolverService
from .rucaptcha import RuCaptchaService
from .azcaptcha import AZCaptchaService
from .captcha_guru import CaptchaGuruService
from .deathbycaptcha import DeathByCaptchaService
from .sctg_captcha import SCTGCaptchaService
from .cptch_net import CptchNetService
from .multibot_captcha import MultibotCaptchaService

__all__ = [
    "BaseService",
    "CapMonsterService",
    "TwoCaptchaService",
    "AntiCaptchaService",
    "CapsolverService",
    "RuCaptchaService",
    "AZCaptchaService",
    "CaptchaGuruService",
    "DeathByCaptchaService",
    "SCTGCaptchaService",
    "CptchNetService",
    "MultibotCaptchaService",
]
