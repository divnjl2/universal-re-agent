"""
CLI entry point for Bybit Manager.

Provides a command-line interface for running batch operations:
- login: Bulk login accounts
- balance: Check balances
- withdraw: Execute withdrawals
- profile: Fetch profiles
- import: Import accounts from Excel
- export: Export accounts to Excel
- browser: Manage AdsPower browser profiles
- imap: Check IMAP connectivity
- kyc: KYC operations
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import List, Optional

from bybit_manager.config import Config
from bybit_manager.manager import Manager
from bybit_manager.license import LicenseChecker
from bybit_manager.paths import ensure_dirs, CONFIG_FILE
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
from bybit_manager.scripts.excel import (
    import_accounts_from_excel,
    export_accounts_to_excel,
)
from bybit_manager.scripts.imap import run_imap_check
from bybit_manager.scripts.kyc import run_kyc_action

CONSOLE_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

logger = logging.getLogger("bybit_manager.console")


def setup_logging(verbose: bool = False) -> None:
    """Configure console logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=CONSOLE_LOG_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_ids(ids_str: str) -> List[int]:
    """Parse comma-separated or range IDs: '1,2,3' or '1-5' or '1,3-5,8'."""
    result = []
    for part in ids_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="bybit-manager",
        description="Bybit Manager v3 — multi-account management CLI",
    )
    parser.add_argument(
        "-c", "--config",
        default=str(CONFIG_FILE),
        help="Path to config.json",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # -- login --
    p_login = sub.add_parser("login", help="Bulk login accounts")
    p_login.add_argument("--ids", type=str, help="Account IDs (e.g. 1,2,3 or 1-5)")
    p_login.add_argument("--group", type=str, help="Group name")
    p_login.add_argument("--concurrency", type=int, default=5)

    # -- balance --
    p_balance = sub.add_parser("balance", help="Check balances")
    p_balance.add_argument("--ids", type=str, help="Account IDs")
    p_balance.add_argument("--group", type=str, help="Group name")
    p_balance.add_argument("--concurrency", type=int, default=10)

    # -- profile --
    p_profile = sub.add_parser("profile", help="Fetch profiles")
    p_profile.add_argument("--ids", type=str, help="Account IDs")
    p_profile.add_argument("--group", type=str, help="Group name")
    p_profile.add_argument("--concurrency", type=int, default=10)

    # -- withdraw --
    p_withdraw = sub.add_parser("withdraw", help="Execute withdrawals")
    p_withdraw.add_argument("--ids", type=str, required=True, help="Account IDs")
    p_withdraw.add_argument("--coin", type=str, required=True)
    p_withdraw.add_argument("--chain", type=str, required=True)
    p_withdraw.add_argument("--address", type=str, required=True)
    p_withdraw.add_argument("--amount", type=float, required=True)
    p_withdraw.add_argument("--concurrency", type=int, default=3)

    # -- import --
    p_import = sub.add_parser("import", help="Import accounts from Excel")
    p_import.add_argument("file", type=str, help="Path to .xlsx file")
    p_import.add_argument("--group", type=str, default="no_group")

    # -- export --
    p_export = sub.add_parser("export", help="Export accounts to Excel")
    p_export.add_argument("file", type=str, help="Output .xlsx path")
    p_export.add_argument("--group", type=str, default=None)

    # -- browser --
    p_browser = sub.add_parser("browser", help="Manage AdsPower profiles")
    p_browser.add_argument(
        "action",
        choices=["create", "open", "close", "delete", "status"],
    )
    p_browser.add_argument("--ids", type=str, help="Account IDs")
    p_browser.add_argument("--group", type=str, help="Group name")

    # -- imap --
    p_imap = sub.add_parser("imap", help="Check IMAP connectivity")
    p_imap.add_argument("--ids", type=str, help="Account IDs")
    p_imap.add_argument("--group", type=str, help="Group name")
    p_imap.add_argument("--concurrency", type=int, default=5)

    # -- kyc --
    p_kyc = sub.add_parser("kyc", help="KYC operations")
    p_kyc.add_argument(
        "action",
        choices=["check_status", "get_requirements", "submit_questionnaire"],
    )
    p_kyc.add_argument("--ids", type=str, help="Account IDs")
    p_kyc.add_argument("--group", type=str, help="Group name")
    p_kyc.add_argument("--concurrency", type=int, default=3)

    return parser


async def _resolve_ids(
    manager: Manager,
    ids_str: Optional[str],
    group: Optional[str],
) -> List[int]:
    """Resolve IDs from --ids or --group arguments."""
    if ids_str:
        return parse_ids(ids_str)
    if group:
        accounts, _ = await manager.get_accounts(group_name=group, page=1, page_size=100000)
        return [a.database_id for a in accounts]
    # No filter — get all
    accounts, _ = await manager.get_accounts(page=1, page_size=100000)
    return [a.database_id for a in accounts]


async def async_main(args: argparse.Namespace) -> int:
    """Async CLI dispatcher."""
    config = Config(args.config)
    manager = Manager(config)
    await manager.init()

    # License check
    checker = LicenseChecker(config.license_key, config.license_server)
    if not await checker.check():
        logger.error("License check failed. Exiting.")
        await manager.shutdown()
        return 1

    try:
        cmd = args.command

        if cmd == "login":
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            req = AccountActionRequest(
                action=AccountActionType.LOGIN,
                database_ids=db_ids,
                concurrency=args.concurrency,
            )
            result = await run_account_action(manager, req)
            _print_result(result.model_dump())

        elif cmd == "balance":
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            req = AccountActionRequest(
                action=AccountActionType.CHECK_BALANCE,
                database_ids=db_ids,
                concurrency=args.concurrency,
            )
            result = await run_account_action(manager, req)
            _print_result(result.model_dump())

        elif cmd == "profile":
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            req = AccountActionRequest(
                action=AccountActionType.GET_PROFILE,
                database_ids=db_ids,
                concurrency=args.concurrency,
            )
            result = await run_account_action(manager, req)
            _print_result(result.model_dump())

        elif cmd == "withdraw":
            db_ids = parse_ids(args.ids)
            req = AccountActionRequest(
                action=AccountActionType.WITHDRAW,
                database_ids=db_ids,
                concurrency=args.concurrency,
                coin=args.coin,
                chain=args.chain,
                address=args.address,
                amount=args.amount,
            )
            result = await run_account_action(manager, req)
            _print_result(result.model_dump())

        elif cmd == "import":
            result = await import_accounts_from_excel(
                manager, args.file, group_name=args.group,
            )
            _print_result(result)

        elif cmd == "export":
            count = await export_accounts_to_excel(
                manager, args.file, group_name=args.group,
            )
            print(f"Exported {count} accounts to {args.file}")

        elif cmd == "browser":
            action_map = {
                "create": BrowserActionType.CREATE_PROFILE,
                "open": BrowserActionType.OPEN_PROFILE,
                "close": BrowserActionType.CLOSE_PROFILE,
                "delete": BrowserActionType.DELETE_PROFILE,
                "status": BrowserActionType.CHECK_STATUS,
            }
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            req = BrowserRequest(
                action=action_map[args.action],
                database_ids=db_ids,
            )
            result = await run_browser_action(manager, req)
            _print_result(result.model_dump())

        elif cmd == "imap":
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            result = await run_imap_check(manager, db_ids, concurrency=args.concurrency)
            _print_result(result)

        elif cmd == "kyc":
            db_ids = await _resolve_ids(manager, getattr(args, "ids", None), getattr(args, "group", None))
            result = await run_kyc_action(
                manager, db_ids, action=args.action, concurrency=args.concurrency,
            )
            _print_result(result)

        else:
            print("No command specified. Use --help for usage.")
            return 1

    finally:
        await manager.shutdown()

    return 0


def _print_result(data) -> None:
    """Print result data in a readable format."""
    import json
    if isinstance(data, dict):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def main() -> None:
    """CLI entry point."""
    ensure_dirs()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    setup_logging(args.verbose)
    exit_code = asyncio.run(async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
