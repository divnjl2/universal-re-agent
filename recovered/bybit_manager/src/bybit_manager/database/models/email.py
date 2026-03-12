"""
SQLAlchemy ORM model for email table — recovered from Alembic migrations.
"""

from sqlalchemy import Boolean, Column, String
from sqlalchemy.orm import relationship

from .base import Base


class Email(Base):
    """Email account — PK: address."""
    __tablename__ = "email"

    address = Column(String(254), primary_key=True)
    imap_address = Column(String(254), nullable=True)
    imap_password = Column(String(128), nullable=True)
    proxy_error = Column(Boolean, server_default="FALSE", nullable=False)
    last_login_failed = Column(Boolean, server_default="FALSE", nullable=False)
    proxy = Column(String, nullable=True)
    client_id = Column(String(100), nullable=True)  # OAuth2 (Outlook)
    refresh_token = Column(String(500), nullable=True)  # OAuth2

    # Relationship
    account = relationship("BybitAccount", back_populates="email", uselist=False)

    def __repr__(self) -> str:
        return f"<Email(address={self.address})>"
