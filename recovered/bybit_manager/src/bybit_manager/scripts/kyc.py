"""
KYC batch operations — submit and check KYC verification for accounts.

KYC flow:
1. Get KYC requirements (which provider, what docs needed)
2. Submit identity documents
3. Poll for verification result
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from bybit_manager.manager import Manager

logger = logging.getLogger("bybit_manager.scripts.kyc")


async def run_kyc_action(
    manager: Manager,
    database_ids: List[int],
    action: str = "check_status",
    concurrency: int = 3,
    **kwargs,
) -> Dict[str, List[Dict[str, Any]]]:
    """Execute KYC-related actions across accounts.

    Supported actions:
    - check_status: Check current KYC level and status
    - get_requirements: Fetch KYC SDK requirements for the account
    - submit_questionnaire: Submit KYC questionnaire (requires answers kwarg)

    Args:
        manager: Manager instance
        database_ids: List of account IDs
        action: One of check_status, get_requirements, submit_kyc
        concurrency: Max parallel operations
        **kwargs: Additional params for submit (first_name, last_name,
                  doc_type, doc_number, country, etc.)
    """
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, List[Dict[str, Any]]] = {"success": [], "failed": []}

    async def _kyc_one(db_id: int):
        async with sem:
            try:
                client = await manager.get_client(db_id)
                private_client = client.client

                if action == "check_status":
                    kyc_info = await private_client.get_kyc_info()
                    kyc_data = kyc_info if isinstance(kyc_info, dict) else {"status": str(kyc_info)}

                    # Update local DB with KYC info
                    update_fields = {}
                    if "kyc_level" in kyc_data:
                        update_fields["kyc_level"] = kyc_data["kyc_level"]
                    if "status" in kyc_data:
                        update_fields["kyc_status"] = kyc_data["status"]
                    if "last_provider" in kyc_data:
                        update_fields["last_provider"] = kyc_data["last_provider"]
                    if "facial_verification_required" in kyc_data:
                        update_fields["facial_verification_required"] = kyc_data["facial_verification_required"]

                    if update_fields:
                        await manager.update_account(db_id, **update_fields)

                    results["success"].append({
                        "database_id": db_id,
                        "kyc": kyc_data,
                    })

                elif action == "get_requirements":
                    reqs = await private_client.get_kyc_sdk()
                    reqs_data = reqs if isinstance(reqs, dict) else {"requirements": str(reqs)}
                    results["success"].append({
                        "database_id": db_id,
                        "requirements": reqs_data,
                    })

                elif action == "submit_questionnaire":
                    answers = kwargs.get("answers", [])
                    resp = await private_client.submit_kyc_questionnaire(answers)
                    resp_data = resp if isinstance(resp, dict) else {"result": str(resp)}
                    results["success"].append({
                        "database_id": db_id,
                        "submission": resp_data,
                    })

                else:
                    results["failed"].append({
                        "database_id": db_id,
                        "error": f"Unknown KYC action: {action}",
                    })

            except Exception as e:
                logger.error("KYC %s failed for %d: %s", action, db_id, e)
                results["failed"].append({
                    "database_id": db_id,
                    "error": str(e),
                })

    await asyncio.gather(*[_kyc_one(db_id) for db_id in database_ids])
    return results
