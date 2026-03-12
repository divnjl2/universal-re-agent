"""
RECOVERED: bybit.password
Skeleton reconstructed from Nuitka binary metadata.
"""
from pydantic import BaseModel, Field

from . import *  # from bybit

# === Constants ===
BYBIT_CARD = None  # RECOVERED
BYBIT_CARD_DEFAULT = None  # RECOVERED
BYBIT_COMPONENT_ERROR = None  # RECOVERED
BYBIT_COOKIES_COLUMN = None  # RECOVERED
BYBIT_COUNTRY_CODE_COLUMN = None  # RECOVERED
BYBIT_ERRORS = None  # RECOVERED
BYBIT_HTML_ERROR = None  # RECOVERED
BYBIT_INVITER_REF_CODE = None  # RECOVERED
BYBIT_JSON_ERROR = None  # RECOVERED
BYBIT_MNEMONIC_PHRASE = None  # RECOVERED
BYBIT_PASSWORD_COLUMN = None  # RECOVERED
BYBIT_PAY = None  # RECOVERED
BYBIT_PROXY_COLUMN = None  # RECOVERED
BYBIT_TOTP_SECRET_COLUMN = None  # RECOVERED
CHALLENGE_PASSWORD = None  # RECOVERED
CLIENT_WAITING_FOR_USERNAME_PASSWORD = None  # RECOVERED
EAS_E_ADMINS_CANNOT_CHANGE_PASSWORD = None  # RECOVERED
EAS_E_ADMINS_HAVE_BLANK_PASSWORD = None  # RECOVERED
EAS_E_CONNECTED_ADMINS_NEED_TO_CHANGE_PASSWORD = None  # RECOVERED
EAS_E_CURRENT_CONNECTED_USER_NEED_TO_CHANGE_PASSWORD = None  # RECOVERED

class BybitCardCommission(object):
    """RECOVERED: BybitCardCommission from bybit.password"""
    pass

class BybitClient(object):
    """RECOVERED: BybitClient from bybit.password"""
    pass

class BybitDevice(object):
    """RECOVERED: BybitDevice from bybit.password"""
    pass

class BybitException(Exception):
    """RECOVERED: BybitException from bybit.password"""
    pass

class BybitHTTPJSONException(Exception):
    """RECOVERED: BybitHTTPJSONException from bybit.password"""
    pass

class BybitResponse(BaseModel):
    """RECOVERED: BybitResponse from bybit.password"""
    pass

class HashablePassword(object):
    """RECOVERED: HashablePassword from bybit.password"""
    pass

class InvalidPassword(object):
    """RECOVERED: InvalidPassword from bybit.password"""
    async def error_code_invalidpassword(self):  # RECOVERED
        raise NotImplementedError

    async def error_invalidpassword(self):  # RECOVERED
        raise NotImplementedError

    async def error_msg_invalidpassword(self):  # RECOVERED
        raise NotImplementedError


class LoginPassword(object):
    """RECOVERED: LoginPassword from bybit.password"""
    pass

class PasswordEncryption(object):
    """RECOVERED: PasswordEncryption from bybit.password"""
    pass
