"""
Custom request execution — send arbitrary API requests through account clients.

Allows sending custom HTTP requests to Bybit API endpoints using account
credentials (cookies, proxy, device fingerprint).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from bybit_manager.manager import Manager

logger = logging.getLogger("bybit_manager.scripts.custom_request")


class CustomRequestParams(BaseModel):
    """Schema for a custom API request."""
    method: str = "GET"
    path: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, str] = Field(default_factory=dict)
    json_body: Optional[Dict[str, Any]] = None
    timeout: int = 30


class CustomRequestResult(BaseModel):
    """Result of a custom API request."""
    database_id: int
    status_code: int = 0
    response_body: Optional[Any] = None
    error: Optional[str] = None


async def run_custom_request(
    manager: Manager,
    database_ids: List[int],
    request: CustomRequestParams,
    concurrency: int = 5,
) -> List[CustomRequestResult]:
    """Execute a custom API request across multiple accounts.

    Uses each account's PrivateClient session (with cookies, proxy, etc.)
    to make the request.
    """
    sem = asyncio.Semaphore(concurrency)
    results: List[CustomRequestResult] = []

    async def _do_one(db_id: int):
        async with sem:
            try:
                client = await manager.get_client(db_id)
                private_client = client.client

                # Use the client's internal _request to make the custom request
                resp = await private_client._request(
                    method=request.method,
                    url=request.path,
                    headers=request.headers,
                    params=request.params,
                    json_data=request.json_body,
                )

                # BybitResponse has .result attribute
                if hasattr(resp, "result"):
                    status_code = 200
                    body = resp.result
                elif isinstance(resp, dict):
                    status_code = 200
                    body = resp
                else:
                    status_code = 200
                    body = str(resp)

                results.append(CustomRequestResult(
                    database_id=db_id,
                    status_code=status_code,
                    response_body=body,
                ))

            except Exception as e:
                logger.error("Custom request failed for %d: %s", db_id, e)
                results.append(CustomRequestResult(
                    database_id=db_id,
                    error=str(e),
                ))

    await asyncio.gather(*[_do_one(db_id) for db_id in database_ids])
    return results
