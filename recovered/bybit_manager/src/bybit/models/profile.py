"""
Bybit user profile models — recovered from memory dump JSON blobs.

The exact field names come from real API responses captured in
memory_dump_8404_20260312_073230.json (JSON blobs 0-5).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class BanStatus(BaseModel):
    """Account ban/restriction status."""
    login: int = 1
    trade: int = 1
    withdraw: int = 1
    is_normal: bool = True
    trade_banned_detail: Optional[Dict[str, Any]] = None
    withdraw_ban_detail: Optional[Dict[str, Any]] = None


class LoyaltyVipInfo(BaseModel):
    """VIP/loyalty program info."""
    is_child_member: bool = False
    is_vip: bool = False
    label_level: int = 0
    label_type: int = 1
    mm_derivative_ended_at: int = 0
    mm_derivative_level: int = 0
    mm_spot_level: str = ""
    vip_status: int = 0


class MemberTag(BaseModel):
    """Account tags (UTA status, etc.)."""
    UTA: str = ""
    UTA_INVERSE: str = ""
    change_utc_time_zone: str = ""
    registered_member_type: str = ""


class GrayFlag(BaseModel):
    """Feature flag/gray release flags."""
    IsFA: bool = False
    IsP2P: bool = False
    IsUTA: bool = False
    isSecureComponent: bool = False
    isSpotConvert: bool = False
    fiatConvert: bool = False
    utaConvert: bool = False
    utaSmallAsset: bool = False

    class Config:
        extra = "allow"


class UserProfile(BaseModel):
    """
    Full user profile from /v2/private/user/profile.
    Fields match the exact JSON structure from memory dump.
    """
    id: int = 0
    username: str = ""
    country_code: str = ""
    status: str = "Normal"
    email_verified: bool = False
    mobile_verified: bool = False
    avatar: str = ""
    auto_add_margin: bool = False
    currency_code: str = ""
    created_at: str = ""
    vague_mobile: str = ""
    vague_email: str = ""
    vague_email_v2: str = ""
    has_google2fa: bool = False
    lang: str = "en"
    use_ws2: bool = False
    use_svc_order: bool = True
    use_order_v2: bool = True
    double_confirm: str = ""
    use_ws2_for_personal: bool = True
    use_webworker: bool = True
    msg_disable_module_ids: str = ""
    ws3_path: str = ""
    account_label: Optional[str] = None
    is_submember: bool = False
    parent_member_id: int = 0
    submember_gray_allow: bool = True
    member_tag: Optional[MemberTag] = None
    credit_card_deposit_gray: Optional[Dict[str, bool]] = None
    ref_id: int = 0
    parent_verify_method: str = ""
    of_affiliate_user: bool = False
    is_wallet_gray_user: bool = False
    banStatus: Optional[BanStatus] = None
    is_deposit: bool = True
    option_gray: bool = False
    asset_gray: bool = False
    has_mt4: bool = False
    is_bot_user: bool = False
    is_copy_trading_leader: bool = False
    is_copy_trading_follower: bool = False
    loyalty_vip_info: Optional[LoyaltyVipInfo] = None
    fullPositionStatus: str = ""
    isFiat: bool = False
    unified_account: int = 0
    platform: str = "pc"
    grayFlag: Optional[GrayFlag] = None

    class Config:
        extra = "allow"


class ProfileResponse(BaseModel):
    """Wrapper for profile API response."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[UserProfile] = None
    ext_info: Optional[Dict[str, Any]] = None
    time_now: Optional[str] = None


class AdsPowerProfile(BaseModel):
    """AdsPower browser profile info for anti-detect."""
    profile_id: str = ""
    name: str = ""
    serial_number: int = 0
    browser_type: str = "chrome"
