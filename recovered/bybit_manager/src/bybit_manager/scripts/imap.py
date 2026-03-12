"""
IMAP batch operations — check email connectivity and fetch codes for accounts.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from bybit_manager.imap import ImapClient
from bybit_manager.manager import Manager

logger = logging.getLogger("bybit_manager.scripts.imap")


async def run_imap_check(
    manager: Manager,
    database_ids: List[int],
    concurrency: int = 5,
) -> Dict[str, List[Dict[str, Any]]]:
    """Check IMAP connectivity for multiple accounts.

    For each account, attempts to connect to the IMAP server and
    reports success/failure. This is useful for validating email
    credentials before running login operations that require email
    verification codes.

    Returns:
        {"success": [...], "failed": [...]}
    """
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, List[Dict[str, Any]]] = {"success": [], "failed": []}

    async def _check_one(db_id: int):
        async with sem:
            try:
                account = await manager.get_account(db_id)
                if not account:
                    results["failed"].append({
                        "database_id": db_id,
                        "error": "Account not found",
                    })
                    return

                # Get email info for IMAP credentials
                async with manager.db.session() as session:
                    from bybit_manager.database.models import Email
                    email_obj = await session.get(Email, account.email_address)

                if not email_obj or not email_obj.imap_address:
                    results["failed"].append({
                        "database_id": db_id,
                        "email": account.email_address,
                        "error": "No IMAP address configured",
                    })
                    return

                imap_client = ImapClient(
                    email_address=account.email_address,
                    password=email_obj.imap_password or account.password or "",
                    imap_address=email_obj.imap_address,
                    client_id=email_obj.client_id,
                    refresh_token=email_obj.refresh_token,
                )

                async with imap_client:
                    # Connection successful
                    results["success"].append({
                        "database_id": db_id,
                        "email": account.email_address,
                        "imap_server": email_obj.imap_address,
                        "status": "connected",
                    })

            except Exception as e:
                logger.error("IMAP check failed for %d: %s", db_id, e)
                results["failed"].append({
                    "database_id": db_id,
                    "error": str(e),
                })

    await asyncio.gather(*[_check_one(db_id) for db_id in database_ids])
    return results
