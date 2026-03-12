"""
Excel column definitions for account import/export.

Maps BybitAccount + Email fields to Excel column headers.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# Column name constants — used by excel.py for import/export
BYBIT_COOKIES_COLUMN = "cookies"
BYBIT_COUNTRY_CODE_COLUMN = "preferred_country_code"
BYBIT_PASSWORD_COLUMN = "password"
BYBIT_PROXY_COLUMN = "proxy"
BYBIT_TOTP_SECRET_COLUMN = "totp_secret"
BYBIT_MNEMONIC_PHRASE = "web3_mnemonic_phrase"
BYBIT_INVITER_REF_CODE = "inviter_ref_code"

EMAIL_IMAP_ADDRESS_COLUMN = "imap_address"
EMAIL_IMAP_PASSWORD_COLUMN = "imap_password"

# (header_name, field_name, is_required)
COLUMNS: List[Tuple[str, str, bool]] = [
    ("email_address", "email_address", True),
    ("password", "password", False),
    ("group_name", "group_name", False),
    ("totp_secret", "totp_secret", False),
    ("proxy", "proxy", False),
    ("preferred_country_code", "preferred_country_code", False),
    ("inviter_ref_code", "inviter_ref_code", False),
    ("imap_address", "imap_address", False),
    ("imap_password", "imap_password", False),
    ("payment_password", "payment_password", False),
    ("name", "name", False),
    ("note", "note", False),
]

# Extended columns for export (include read-only / computed fields)
EXPORT_COLUMNS: List[Tuple[str, str]] = [
    ("database_id", "database_id"),
    ("uid", "uid"),
    ("email_address", "email_address"),
    ("password", "password"),
    ("group_name", "group_name"),
    ("totp_secret", "totp_secret"),
    ("proxy", "proxy"),
    ("preferred_country_code", "preferred_country_code"),
    ("inviter_ref_code", "inviter_ref_code"),
    ("imap_address", "imap_address"),
    ("imap_password", "imap_password"),
    ("registered", "registered"),
    ("kyc_level", "kyc_level"),
    ("kyc_status", "kyc_status"),
    ("balance_usd", "balance_usd"),
    ("is_uta", "is_uta"),
    ("email_verified", "email_verified"),
    ("totp_enabled", "totp_enabled"),
    ("web3_mnemonic_phrase", "web3_mnemonic_phrase"),
    ("cookies", "cookies"),
    ("name", "name"),
    ("note", "note"),
    ("payment_password", "payment_password"),
]

# Address-related columns for withdraw address import
ADDRESS_COLUMNS: List[Tuple[str, str, bool]] = [
    ("coin", "coin_symbol", True),
    ("chain", "chain_type", True),
    ("address", "address", True),
    ("tag", "tag", False),
    ("note", "note", False),
]
