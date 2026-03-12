"""
ByVote models — voting campaign data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VoteCampaign:
    """Voting campaign info."""
    vote_id: int = 0
    name: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    options: List["VoteOption"] = field(default_factory=list)


@dataclass
class VoteOption:
    """Voting option."""
    option_id: int = 0
    name: str = ""
    coin_symbol: str = ""
    votes: int = 0


@dataclass
class VoteResult:
    """User vote result."""
    vote_id: int = 0
    voted: bool = False
    option_id: int = 0
    votes_used: int = 0
