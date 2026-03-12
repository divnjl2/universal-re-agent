"""
AirdropHunt models — airdrop campaign data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AirdropHuntCampaign:
    """Airdrop hunt campaign info."""
    code: int = 0
    name: str = ""
    coin_symbol: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    total_airdrop: float = 0.0
    min_volume: float = 0.0
    questionnaire_required: bool = False


@dataclass
class AirdropHuntParticipation:
    """User participation in an airdrop hunt."""
    code: int = 0
    registered: bool = False
    completed: bool = False
    spent_usdt: float = 0.0
    form_submitted: bool = False
    answers: Optional[Dict[str, Any]] = None


@dataclass
class AirdropHuntQuestionnaire:
    """Airdrop hunt questionnaire."""
    code: int = 0
    questions: List[Dict[str, Any]] = field(default_factory=list)
