"""
SQLAlchemy declarative base for all database models.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """SQLAlchemy declarative base class."""
    __allow_unmapped__ = True
