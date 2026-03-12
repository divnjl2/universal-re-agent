"""
Anycaptcha error types — recovered from memory dump constants.
"""


class AnyCaptchaException(Exception):
    """Base captcha exception."""
    pass


class CaptchaError(AnyCaptchaException):
    """Error during captcha solving."""
    pass


class CaptchaTimeout(AnyCaptchaException):
    """Captcha solving timed out."""
    pass


class CaptchaUnsolvable(AnyCaptchaException):
    """Captcha could not be solved."""
    pass


class CaptchaServiceError(AnyCaptchaException):
    """Error from the captcha service API."""
    pass


class CaptchaInvalidKey(CaptchaServiceError):
    """Invalid API key for captcha service."""
    pass


class CaptchaNoBalance(CaptchaServiceError):
    """No balance on captcha service account."""
    pass
