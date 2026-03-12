"""
FSM states for multi-step interactions.

From memory: tg_bot.states

States are used for:
  - Admin: mailing, set welcome, set FAQ, country price editing
  - User: wallet setup, note input
"""
from __future__ import annotations

from aiogram.fsm.state import State, StatesGroup


class AdminMailingStates(StatesGroup):
    """States for admin mailing flow."""
    waiting_message = State()
    waiting_schedule_datetime = State()
    confirm_send = State()


class AdminSetWelcomeStates(StatesGroup):
    """States for setting welcome message."""
    waiting_message = State()


class AdminSetFaqStates(StatesGroup):
    """States for setting FAQ message."""
    waiting_message = State()


class AdminCountryPriceStates(StatesGroup):
    """States for editing country prices."""
    waiting_price = State()
    waiting_reverify_price = State()
    waiting_limit = State()


class AdminGiveStates(StatesGroup):
    """States for /give command flow."""
    waiting_count = State()
    waiting_country = State()


class UserNoteStates(StatesGroup):
    """States for user note input."""
    waiting_note = State()


class UserWalletStates(StatesGroup):
    """States for /set_wallet command."""
    waiting_address = State()
