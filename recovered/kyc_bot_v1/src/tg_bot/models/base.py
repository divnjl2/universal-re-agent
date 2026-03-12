"""
SQLAlchemy declarative base for all models.

Uses the shared 'bybit' PostgreSQL database (same DB as Bybit Manager v3).
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass
