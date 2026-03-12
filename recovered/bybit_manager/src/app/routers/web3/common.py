"""
Common schemas for web3 router endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class Web3BulkRequest(BaseModel):
    """Base request for web3 bulk operations."""
    database_ids: List[int]


class Web3BulkResult(BaseModel):
    """Result of web3 bulk operations."""
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)
