"""
Common constants and utilities used across database models.

Recovered from Nuitka binary metadata — column name constants for
programmatic access to BybitAccount fields.
"""

# Column name constants (used by import/export and bulk operations)
BYBIT_PASSWORD_COLUMN = "password"
BYBIT_COOKIES_COLUMN = "cookies"
BYBIT_PROXY_COLUMN = "proxy"
BYBIT_TOTP_SECRET_COLUMN = "totp_secret"
BYBIT_COUNTRY_CODE_COLUMN = "preferred_country_code"
BYBIT_INVITER_REF_CODE = "inviter_ref_code"
BYBIT_MNEMONIC_PHRASE = "web3_mnemonic_phrase"

# CJK character sets (used for name validation in KYC flows)
COMMON_CHINESE_CHARACTERS = (
    "\u4e00-\u9fff"  # CJK Unified Ideographs
)
COMMON_JAPANESE_CHARACTERS = (
    "\u3040-\u309f"  # Hiragana
    "\u30a0-\u30ff"  # Katakana
)
COMMON_KOREAN_CHARACTERS = (
    "\uac00-\ud7af"  # Hangul Syllables
)
COMMON_CJK_CHARACTERS = (
    COMMON_CHINESE_CHARACTERS
    + COMMON_JAPANESE_CHARACTERS
    + COMMON_KOREAN_CHARACTERS
)
