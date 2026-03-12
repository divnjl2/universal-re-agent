"""
PuzzleHunt models — puzzle hunt campaign data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PuzzleHuntCampaign:
    """Puzzle hunt campaign info."""
    code: int = 0
    name: str = ""
    coin_symbol: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    total_prize: float = 0.0


@dataclass
class PuzzleHuntParticipation:
    """User participation in a puzzle hunt."""
    code: int = 0
    registered: bool = False
    social_tasks_completed: bool = False
    checkin_count: int = 0
    piece_count: int = 0
    reward_amount: float = 0.0
    volume_usdt: float = 0.0
