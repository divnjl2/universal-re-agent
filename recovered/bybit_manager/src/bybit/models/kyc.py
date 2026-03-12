"""
Bybit KYC models — recovered from memory dump.

KYC enums from DB schema:
- kycstatus: ALLOW, NOT_ALLOW, PENDING, SUCCESS, FAILED_AND_CAN_RETRY,
             FAILED_AND_CAN_NOT_RETRY, CERTIFICATION_DISABLED
- kycprovider: PROVIDER_SUMSUB, PROVIDER_ONFIDO, PROVIDER_JUMIO,
               PROVIDER_AAI, PROVIDER_DEFAULT

Doc types from memory:
KYC_DOC_TYPE_UNDEFINED, KYC_DOC_TYPE_ID, KYC_DOC_TYPE_PASSPORT,
KYC_DOC_TYPE_DL, KYC_DOC_TYPE_LIVING_PERMITS, KYC_DOC_TYPE_BVN
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class KycStatus(str, Enum):
    """KYC verification status."""
    ALLOW = "ALLOW"
    NOT_ALLOW = "NOT_ALLOW"
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED_AND_CAN_RETRY = "FAILED_AND_CAN_RETRY"
    FAILED_AND_CAN_NOT_RETRY = "FAILED_AND_CAN_NOT_RETRY"
    CERTIFICATION_DISABLED = "CERTIFICATION_DISABLED"


class KycProvider(str, Enum):
    """KYC verification provider."""
    PROVIDER_SUMSUB = "PROVIDER_SUMSUB"
    PROVIDER_ONFIDO = "PROVIDER_ONFIDO"
    PROVIDER_JUMIO = "PROVIDER_JUMIO"
    PROVIDER_AAI = "PROVIDER_AAI"
    PROVIDER_DEFAULT = "PROVIDER_DEFAULT"


class KycDocType(str, Enum):
    """KYC document types."""
    UNDEFINED = "KYC_DOC_TYPE_UNDEFINED"
    ID = "KYC_DOC_TYPE_ID"
    PASSPORT = "KYC_DOC_TYPE_PASSPORT"
    DRIVING_LICENSE = "KYC_DOC_TYPE_DL"
    LIVING_PERMITS = "KYC_DOC_TYPE_LIVING_PERMITS"
    BVN = "KYC_DOC_TYPE_BVN"


class KycInfo(BaseModel):
    """KYC verification info from /v3/private/kyc/kyc-info."""
    kyc_level: int = 0
    kyc_status: str = ""
    provider: str = ""
    country: str = ""
    first_name: str = ""
    last_name: str = ""
    doc_type: str = ""
    doc_number: str = ""
    need_questionnaire: bool = False
    facial_verification_required: bool = False
    conflict: bool = False
    conflict_uid: Optional[int] = None

    class Config:
        extra = "allow"


class KycRequiredInfo(BaseModel):
    """Required KYC info for verification."""
    level: int = 0
    provider: str = ""
    country: str = ""
    doc_types: List[str] = Field(default_factory=list)


class KycSdkInfo(BaseModel):
    """KYC SDK info from provider."""
    provider: str = ""
    sdk_token: str = ""
    sdk_url: str = ""
    level: int = 0

    class Config:
        extra = "allow"
