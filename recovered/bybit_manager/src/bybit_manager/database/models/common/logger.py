"""
Database operation logging utilities.

Recovered from Nuitka binary — provides structured logging
for database CRUD operations.
"""

import logging
from typing import Any

logger = logging.getLogger("bybit_manager.database")


def log_db_operation(operation: str, table: str, **kwargs: Any) -> None:
    """Log a database operation with context."""
    details = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.debug("%s %s %s", operation, table, details)
