"""
FastAPI routers — all API endpoint groups.
"""

from .awarding import router as awarding_router
from .byfi import router as byfi_router
from .byvote import router as byvote_router
from .captcha import router as captcha_router
from .contract import router as contract_router
from .database import router as database_router
from .demo_trading import router as demo_trading_router
from .email import router as email_router
from .ido import router as ido_router
from .imap import router as imap_router
from .kyc import router as kyc_router
from .launchpad import router as launchpad_router
from .launchpool import router as launchpool_router
from .private import router as private_router
from .public import router as public_router
from .puzzlehunt import router as puzzlehunt_router
from .referral import router as referral_router
from .spot import router as spot_router
from .tokensplash import router as tokensplash_router
from .transfer import router as transfer_router
from .web3 import router as web3_detail_router
from .web3 import router as web3_router
from .withdraw import router as withdraw_router
