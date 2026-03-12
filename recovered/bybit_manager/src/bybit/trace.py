"""
RECOVERED: bybit.trace
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
DEBUG_CALLTRACE_FORMATTERS = None  # RECOVERED
DEBUG_CALLTRACE_LOG_ENTRY_FORMATTERS = None  # RECOVERED
DEBUG_TRACE_FORMATTERS = None  # RECOVERED
ERROR_SYSTEM_TRACE = None  # RECOVERED
LOGURU_BACKTRACE = None  # RECOVERED
LOGURU_TRACE_COLOR = None  # RECOVERED

class BlockTrace(object):
    """RECOVERED: BlockTrace from bybit.trace"""
    pass

class BybitCardCommission(object):
    """RECOVERED: BybitCardCommission from bybit.trace"""
    pass

class BybitClient(object):
    """RECOVERED: BybitClient from bybit.trace"""
    pass

class BybitDevice(object):
    """RECOVERED: BybitDevice from bybit.trace"""
    pass

class BybitException(Exception):
    """RECOVERED: BybitException from bybit.trace"""
    pass

class BybitHTTPJSONException(Exception):
    """RECOVERED: BybitHTTPJSONException from bybit.trace"""
    pass

class BybitResponse(BaseModel):
    """RECOVERED: BybitResponse from bybit.trace"""
    pass

class CallTrace(object):
    """RECOVERED: CallTrace from bybit.trace"""
    async def debug_calltrace_list_result_formatter(self):  # RECOVERED
        raise NotImplementedError

    async def debug_calltrace_log_list_result_formatter(self):  # RECOVERED
        raise NotImplementedError

    async def debug_calltrace_result_formatter(self):  # RECOVERED
        raise NotImplementedError


class CallTraceLog(object):
    """RECOVERED: CallTraceLog from bybit.trace"""
    pass

class DiffModeTrace(object):
    """RECOVERED: DiffModeTrace from bybit.trace"""
    pass
