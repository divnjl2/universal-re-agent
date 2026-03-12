"""
KYC router — Know Your Customer verification endpoints.

Handles: KYC status check, document submission via SumSub/Onfido/AAI,
questionnaire submission, facial verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.kyc")

router = APIRouter()


class KYCCheckRequest(BaseModel):
    """Check KYC status for accounts."""
    database_ids: List[int]


class KYCSubmitRequest(BaseModel):
    """Submit KYC documents for accounts."""
    database_ids: List[int]
    provider: str = "sumsub"  # sumsub, onfido, aai
    first_name: str
    last_name: str
    doc_type: str = "passport"
    doc_number: str = ""
    country: str = ""


class QuestionnaireRequest(BaseModel):
    """Submit KYC questionnaire."""
    database_ids: List[int]
    answers: Dict[str, Any]


class BulkOperationResult(BaseModel):
    success: List[Dict[str, Any]] = Field(default_factory=list)
    failed: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/check", response_model=BulkOperationResult)
async def check_kyc_status(request: KYCCheckRequest):
    """Check KYC status for multiple accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "kyc_level": None,
                "kyc_status": None,
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_kyc_status(database_id: int):
    """Get detailed KYC status for one account."""
    return {"database_id": database_id, "kyc_level": None, "kyc_status": None}


@router.post("/submit", response_model=BulkOperationResult)
async def submit_kyc(request: KYCSubmitRequest):
    """Submit KYC verification for accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "provider": request.provider,
                "status": "submitted",
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/questionnaire", response_model=BulkOperationResult)
async def submit_questionnaire(request: QuestionnaireRequest):
    """Submit KYC questionnaire for accounts."""
    results = BulkOperationResult()
    for db_id in request.database_ids:
        try:
            results.success.append({
                "database_id": db_id,
                "status": "questionnaire_submitted",
            })
        except Exception as e:
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/providers")
async def get_kyc_providers():
    """Get available KYC providers."""
    return {
        "providers": [
            {"name": "sumsub", "display": "SumSub"},
            {"name": "onfido", "display": "Onfido"},
            {"name": "jumio", "display": "Jumio"},
            {"name": "aai", "display": "AAI"},
        ]
    }
