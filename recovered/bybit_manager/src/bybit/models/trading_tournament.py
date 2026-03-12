"""
Trading tournament models — demo trading tournament data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TradingTournament:
    """Demo trading tournament info."""
    tournament_id: int = 0
    name: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    initial_balance: float = 100000.0
    prize_pool: float = 0.0


@dataclass
class TournamentParticipation:
    """User participation in a trading tournament."""
    tournament_id: int = 0
    registered: bool = False
    pnl: float = 0.0
    rank: int = 0
    trading_volume: float = 0.0
