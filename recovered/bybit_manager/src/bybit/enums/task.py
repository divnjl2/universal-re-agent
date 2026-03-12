"""
Task-related enums.
"""

from __future__ import annotations

from ._base import BybitEnum


class TaskStatus(BybitEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    EXPIRED = "expired"


class TaskType(BybitEnum):
    TRADE = "trade"
    DEPOSIT = "deposit"
    KYC = "kyc"
    SOCIAL = "social"
    DAILY_CHECKIN = "daily_checkin"
    QUIZ = "quiz"
