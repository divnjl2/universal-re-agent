"""
Combined schemas for running all script operations together.

Provides AllSchemas — a unified request model that can dispatch
to any of the individual script modules.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from bybit_manager.manager import Manager
from bybit_manager.scripts.account_action import (
    AccountActionType,
    AccountActionRequest,
    run_account_action,
)
from bybit_manager.scripts.browser import (
    BrowserActionType,
    BrowserRequest,
    run_browser_action,
)
from bybit_manager.scripts.custom_request import (
    CustomRequestParams,
    run_custom_request,
)
from bybit_manager.scripts.excel import (
    import_accounts_from_excel,
    export_accounts_to_excel,
)
from bybit_manager.scripts.imap import run_imap_check
from bybit_manager.scripts.kyc import run_kyc_action

logger = logging.getLogger("bybit_manager.scripts.all")


class AllSchemas(BaseModel):
    """Unified request schema that can dispatch to any script action.

    Set exactly one of: account_action, browser_action, custom_request,
    excel_import, excel_export, imap_check, kyc_action.
    """
    # Account actions
    account_action: Optional[AccountActionRequest] = None

    # Browser actions
    browser_action: Optional[BrowserRequest] = None

    # Custom request
    custom_request: Optional[CustomRequestParams] = None
    custom_request_database_ids: List[int] = Field(default_factory=list)
    custom_request_concurrency: int = 5

    # Excel
    excel_import_path: Optional[str] = None
    excel_import_group: str = "no_group"
    excel_export_path: Optional[str] = None
    excel_export_group: Optional[str] = None

    # IMAP check
    imap_check_database_ids: List[int] = Field(default_factory=list)
    imap_check_concurrency: int = 5

    # KYC
    kyc_action: Optional[str] = None
    kyc_database_ids: List[int] = Field(default_factory=list)
    kyc_concurrency: int = 3
    kyc_kwargs: Dict[str, Any] = Field(default_factory=dict)


async def run_all(manager: Manager, schema: AllSchemas) -> Dict[str, Any]:
    """Dispatch to the appropriate script based on what's set in schema."""
    results: Dict[str, Any] = {}

    if schema.account_action:
        results["account_action"] = await run_account_action(
            manager, schema.account_action,
        )

    if schema.browser_action:
        results["browser_action"] = await run_browser_action(
            manager, schema.browser_action,
        )

    if schema.custom_request and schema.custom_request_database_ids:
        results["custom_request"] = await run_custom_request(
            manager,
            schema.custom_request_database_ids,
            schema.custom_request,
            concurrency=schema.custom_request_concurrency,
        )

    if schema.excel_import_path:
        results["excel_import"] = await import_accounts_from_excel(
            manager,
            schema.excel_import_path,
            group_name=schema.excel_import_group,
        )

    if schema.excel_export_path:
        results["excel_export"] = await export_accounts_to_excel(
            manager,
            schema.excel_export_path,
            group_name=schema.excel_export_group,
        )

    if schema.imap_check_database_ids:
        results["imap_check"] = await run_imap_check(
            manager,
            schema.imap_check_database_ids,
            concurrency=schema.imap_check_concurrency,
        )

    if schema.kyc_action and schema.kyc_database_ids:
        results["kyc"] = await run_kyc_action(
            manager,
            schema.kyc_database_ids,
            action=schema.kyc_action,
            concurrency=schema.kyc_concurrency,
            **schema.kyc_kwargs,
        )

    return results
