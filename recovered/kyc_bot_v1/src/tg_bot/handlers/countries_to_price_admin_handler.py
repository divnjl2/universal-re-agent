"""
Country pricing admin handler — DEPRECATED.

All country price management functionality has been moved to
user_payment_handler.py which uses the real callback patterns:
  country_<id>, toggle_country_<id>, upd_country_price_<id>,
  upd_country_reverify_price_<id>, upd_country_limit_<id>

This file is kept for backwards compatibility but contains no routes.
The router is still registered in start_bot.py but does nothing.
"""
from __future__ import annotations

from aiogram import Router

router = Router(name="countries_price_admin")

# All functionality moved to user_payment_handler.py
# See: admin_change_prices, country_<id>, toggle_country_<id>,
#      upd_country_price_<id>, upd_country_reverify_price_<id>,
#      upd_country_limit_<id>
