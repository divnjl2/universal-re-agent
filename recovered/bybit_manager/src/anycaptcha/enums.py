"""
Anycaptcha enums — captcha types, services, and status codes.
"""

from enum import Enum


class CaptchaType(str, Enum):
    RECAPTCHA_V2 = "RecaptchaV2"
    RECAPTCHA_V3 = "RecaptchaV3"
    HCAPTCHA = "HCaptcha"
    FUNCAPTCHA = "FunCaptcha"
    GEETEST = "GeeTest"
    GEETEST_V4 = "GeeTestV4"
    IMAGE = "Image"
    TEXT = "Text"
    KEYCAPTCHA = "KeyCaptcha"
    CAPY = "Capy"


class CaptchaServiceType(str, Enum):
    CAPMONSTER = "capmonster"
    ANTI_CAPTCHA = "anti_captcha"
    TWO_CAPTCHA = "2captcha"
    RUCAPTCHA = "rucaptcha"
    CAPSOLVER = "capsolver"
    AZCAPTCHA = "azcaptcha"
    CAPTCHA_GURU = "captcha_guru"
    DEATHBYCAPTCHA = "deathbycaptcha"
    SCTG = "sctg"
    CPTCH_NET = "cptch_net"
    MULTIBOT = "multibot"


class TaskStatus(str, Enum):
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"


class CaptchaAlphabet(int, Enum):
    LATIN = 1
    CYRILLIC = 2
    LATIN_AND_CYRILLIC = 3


class CaptchaCharType(int, Enum):
    ANY = 0
    NUMBERS_ONLY = 1
    LETTERS_ONLY = 2
