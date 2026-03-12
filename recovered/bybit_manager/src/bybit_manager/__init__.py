"""
Bybit Manager v3 — multi-account Bybit management platform.

Core modules:
- config: Configuration from config.json
- manager: Central orchestrator
- client: Managed API client wrapper
- database: SQLAlchemy ORM models + async DB
- imap: Email verification code retrieval
- captcha: Captcha solving integration
- license: License validation
"""

from .config import Config
from .manager import Manager

__all__ = ["Config", "Manager"]
