"""
Web3 router sub-package — additional web3 endpoints.
"""

from fastapi import APIRouter

from .activity import router as activity_router
from .staking import router as staking_router

router = APIRouter()
router.include_router(activity_router, prefix="/activity", tags=["web3-activity"])
router.include_router(staking_router, prefix="/staking", tags=["web3-staking"])
