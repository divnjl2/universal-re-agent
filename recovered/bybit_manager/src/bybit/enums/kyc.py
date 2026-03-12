"""
KYC enums.
"""

from __future__ import annotations

from ._base import BybitEnum


class KycStatus(BybitEnum):
    ALLOW = "ALLOW"
    NOT_ALLOW = "NOT_ALLOW"
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED_CAN_RETRY = "FAILED_AND_CAN_RETRY"
    FAILED_CANNOT_RETRY = "FAILED_AND_CAN_NOT_RETRY"
    DISABLED = "CERTIFICATION_DISABLED"


class KycProvider(BybitEnum):
    SUMSUB = "PROVIDER_SUMSUB"
    ONFIDO = "PROVIDER_ONFIDO"
    JUMIO = "PROVIDER_JUMIO"
    AAI = "PROVIDER_AAI"
    DEFAULT = "PROVIDER_DEFAULT"


class KycDocType(BybitEnum):
    PASSPORT = "passport"
    ID_CARD = "id_card"
    DRIVERS_LICENSE = "drivers_license"
    RESIDENCE_PERMIT = "residence_permit"
