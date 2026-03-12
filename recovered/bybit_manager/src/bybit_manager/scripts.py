"""
bybit_manager.scripts — convenience re-exports from scripts/ sub-package.

This module provides a flat namespace for all script operations so callers
can do:
    from bybit_manager.scripts import run_account_action, import_accounts_from_excel
"""

from bybit_manager.scripts.account_action import (
    AccountActionType,
    AccountActionRequest,
    AccountActionResponse,
    run_account_action,
)
from bybit_manager.scripts.browser import (
    BrowserActionType,
    BrowserRequest,
    BrowserResponse,
    run_browser_action,
)
from bybit_manager.scripts.custom_request import (
    CustomRequestParams,
    CustomRequestResult,
    run_custom_request,
)
from bybit_manager.scripts.excel import (
    import_accounts_from_excel,
    export_accounts_to_excel,
)
from bybit_manager.scripts.imap import run_imap_check
from bybit_manager.scripts.kyc import run_kyc_action
from bybit_manager.scripts.all import AllSchemas, run_all
from bybit_manager.scripts._excel_columns import (
    COLUMNS,
    EXPORT_COLUMNS,
    ADDRESS_COLUMNS,
    BYBIT_COOKIES_COLUMN,
    BYBIT_COUNTRY_CODE_COLUMN,
    BYBIT_PASSWORD_COLUMN,
    BYBIT_PROXY_COLUMN,
    BYBIT_TOTP_SECRET_COLUMN,
    BYBIT_MNEMONIC_PHRASE,
    BYBIT_INVITER_REF_CODE,
    EMAIL_IMAP_ADDRESS_COLUMN,
    EMAIL_IMAP_PASSWORD_COLUMN,
)

__all__ = [
    # Account actions
    "AccountActionType",
    "AccountActionRequest",
    "AccountActionResponse",
    "run_account_action",
    # Browser
    "BrowserActionType",
    "BrowserRequest",
    "BrowserResponse",
    "run_browser_action",
    # Custom request
    "CustomRequestParams",
    "CustomRequestResult",
    "run_custom_request",
    # Excel
    "import_accounts_from_excel",
    "export_accounts_to_excel",
    # IMAP
    "run_imap_check",
    # KYC
    "run_kyc_action",
    # All
    "AllSchemas",
    "run_all",
    # Column constants
    "COLUMNS",
    "EXPORT_COLUMNS",
    "ADDRESS_COLUMNS",
    "BYBIT_COOKIES_COLUMN",
    "BYBIT_COUNTRY_CODE_COLUMN",
    "BYBIT_PASSWORD_COLUMN",
    "BYBIT_PROXY_COLUMN",
    "BYBIT_TOTP_SECRET_COLUMN",
    "BYBIT_MNEMONIC_PHRASE",
    "BYBIT_INVITER_REF_CODE",
    "EMAIL_IMAP_ADDRESS_COLUMN",
    "EMAIL_IMAP_PASSWORD_COLUMN",
]
