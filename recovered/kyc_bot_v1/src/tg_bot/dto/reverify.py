"""
Reverify DTOs — data objects for re-verification flow.

From memory: tg_bot.dto.reverify
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ReverifyAccountInfo:
    """Account info prepared for re-verification display."""
    database_id: int
    uid: Optional[int]
    name: Optional[str]
    country: Optional[str]
    kyc_status: Optional[str]
    kyc_level: Optional[int]
    last_provider: Optional[str]
    facial_verification_required: Optional[bool]
    first_name: Optional[str] = None
    last_name: Optional[str] = None


@dataclass
class ReverifyResult:
    """Result of a re-verification attempt."""
    success: bool
    account_id: int
    message: str = ""
    verification_url: Optional[str] = None
    face_link: Optional[str] = None
    error: Optional[str] = None
