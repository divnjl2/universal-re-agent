"""
UserDTO — data transfer object for user info.

From memory:
  tg_bot.dto.user.UserDTO
  UserDTO.is_admin
  UserDTO.mention
  UserDTO.url
  UserDTO.__repr__
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class UserDTO:
    """
    Lightweight user representation for passing between layers.

    Properties recovered from memory: is_admin, mention, url.
    """
    id: int
    full_name: Optional[str] = None
    username: Optional[str] = None
    group: Optional[str] = None
    active: bool = True
    need_pay: bool = True
    wallet_address: Optional[str] = None
    pinned: bool = False
    provider: Optional[str] = None
    can_take_accounts: bool = True
    invited_by: Optional[int] = None
    balance: float = 0.0
    admin_ids: list[int] | None = None

    @property
    def is_admin(self) -> bool:
        """Check if this user is an admin."""
        if self.admin_ids:
            return self.id in self.admin_ids
        return False

    @property
    def mention(self) -> str:
        """Return an HTML mention link."""
        display = self.full_name or self.username or str(self.id)
        return f'<a href="tg://user?id={self.id}">{display}</a>'

    @property
    def url(self) -> str:
        """Return t.me link if username is set."""
        if self.username:
            return f"https://t.me/{self.username}"
        return f"tg://user?id={self.id}"

    def __repr__(self) -> str:
        return f"UserDTO(id={self.id}, name={self.full_name}, group={self.group})"
