"""
IDO / Launchpad enums.
"""

from __future__ import annotations

from ._base import BybitEnum


class IDOStatus(BybitEnum):
    UPCOMING = "upcoming"
    ONGOING = "ongoing"
    CALCULATION = "calculation"
    DISTRIBUTION = "distribution"
    ENDED = "ended"


class IDOCommitStatus(BybitEnum):
    NOT_COMMITTED = "not_committed"
    COMMITTED = "committed"
    WON = "won"
    LOST = "lost"
    REDEEMED = "redeemed"
