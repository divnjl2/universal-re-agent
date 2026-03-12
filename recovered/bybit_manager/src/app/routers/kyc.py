"""
KYC router — Know Your Customer verification endpoints.

Handles: KYC status check, document submission via SumSub/Onfido/AAI,
questionnaire submission, facial verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("app.routers.kyc")

router = APIRouter()


def _get_manager(request: Request):
    return request.app.state.manager


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
async def check_kyc_status(body: KYCCheckRequest, request: Request):
    """Check KYC status for multiple accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.get_kyc_info()
            kyc_data = resp.result if hasattr(resp, "result") else {}
            kyc_level = None
            kyc_status = None
            if isinstance(kyc_data, dict):
                kyc_level = kyc_data.get("kyc_level", kyc_data.get("level"))
                kyc_status = kyc_data.get("kyc_status", kyc_data.get("status"))
            # Persist to DB
            await manager.update_account(
                db_id,
                kyc_level=kyc_level,
                kyc_status=kyc_status,
            )
            results.success.append({
                "database_id": db_id,
                "kyc_level": kyc_level,
                "kyc_status": kyc_status,
                "details": kyc_data,
            })
        except Exception as e:
            logger.error("KYC check failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.get("/status/{database_id}")
async def get_kyc_status(database_id: int, request: Request):
    """Get detailed KYC status for one account."""
    manager = _get_manager(request)
    try:
        client = await manager.get_client(database_id)
        resp = await client.client.get_kyc_info()
        kyc_data = resp.result if hasattr(resp, "result") else {}
        kyc_level = None
        kyc_status = None
        if isinstance(kyc_data, dict):
            kyc_level = kyc_data.get("kyc_level", kyc_data.get("level"))
            kyc_status = kyc_data.get("kyc_status", kyc_data.get("status"))
        return {
            "database_id": database_id,
            "kyc_level": kyc_level,
            "kyc_status": kyc_status,
            "details": kyc_data,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit", response_model=BulkOperationResult)
async def submit_kyc(body: KYCSubmitRequest, request: Request):
    """Submit KYC verification for accounts.

    NOTE: Full KYC document submission requires provider SDK integration
    (SumSub/Onfido/AAI) which depends on external services. This endpoint
    sets the provider; actual document upload flows are provider-specific.
    """
    manager = _get_manager(request)
    results = BulkOperationResult()
    provider_map = {
        "sumsub": "PROVIDER_SUMSUB",
        "onfido": "PROVIDER_ONFIDO",
        "aai": "PROVIDER_AAI",
        "jumio": "PROVIDER_JUMIO",
    }
    provider_value = provider_map.get(body.provider.lower(), f"PROVIDER_{body.provider.upper()}")
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.set_kyc_provider(provider=provider_value)
            results.success.append({
                "database_id": db_id,
                "provider": body.provider,
                "status": "provider_set",
                "result": resp.result if hasattr(resp, "result") else {},
            })
        except Exception as e:
            logger.error("KYC submit failed for %d: %s", db_id, e)
            results.failed.append({"database_id": db_id, "error": str(e)})
    return results


@router.post("/questionnaire", response_model=BulkOperationResult)
async def submit_questionnaire(body: QuestionnaireRequest, request: Request):
    """Submit KYC questionnaire for accounts."""
    manager = _get_manager(request)
    results = BulkOperationResult()
    # Convert dict answers to list format expected by the API
    answers_list = [
        {"question": k, "answer": v} for k, v in body.answers.items()
    ] if isinstance(body.answers, dict) else body.answers
    for db_id in body.database_ids:
        try:
            client = await manager.get_client(db_id)
            resp = await client.client.submit_kyc_questionnaire(answers_list)
            results.success.append({
                "database_id": db_id,
                "status": "questionnaire_submitted",
            })
        except Exception as e:
            logger.error("Questionnaire submit failed for %d: %s", db_id, e)
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
