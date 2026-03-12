"""
Web3 router sub-package — all web3 endpoints.

Includes: wallet ops (create, balance, swap, stake, chains),
activity (IDO, airdrops), and DeFi staking.
"""

from fastapi import APIRouter

from .activity import router as activity_router
from .staking import router as staking_router
from .wallet import router as wallet_router

router = APIRouter()
# Main wallet/swap/stake endpoints at the web3 root
router.include_router(wallet_router)
# Sub-groups
router.include_router(activity_router, prefix="/activity", tags=["web3-activity"])
router.include_router(staking_router, prefix="/staking", tags=["web3-staking"])
