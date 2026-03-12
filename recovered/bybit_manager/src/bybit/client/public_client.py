"""
Bybit PublicClient — recovered from Nuitka binary + memory dump.

Public (no auth) API methods for market data, instruments, contracts, etc.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import aiohttp

from .base import BASE_URL, BaseClient, BybitDevice, BybitResponse

logger = logging.getLogger("bybit.client.public")


class PublicClient(BaseClient):
    """Public Bybit API client — no authentication required."""

    # Contract types for kline requests
    CONTRACT_LINEAR = "linear"
    CONTRACT_INVERSE = "inverse"

    def __init__(
        self,
        proxy: Optional[str] = None,
        base_url: str = BASE_URL,
        locale: str = "en",
    ):
        super().__init__(proxy=proxy, base_url=base_url, locale=locale)

    # ================================================================
    # MARKET DATA
    # ================================================================

    async def get_system_time(self) -> BybitResponse:
        """Get Bybit server time."""
        return await self.get("/v3/public/time")

    async def get_trade_pairs(self) -> BybitResponse:
        """Get all available spot trading pairs."""
        return await self.get("/v3/public/spot/trade/pairs")

    async def get_trade_pair(self, symbol: str) -> BybitResponse:
        """Get a specific spot trading pair info."""
        return await self.get("/v3/public/spot/trade/pair", params={"symbol": symbol})

    async def get_trading_precision(self, symbol: str) -> BybitResponse:
        """Get trading precision for a symbol."""
        return await self.get("/v3/public/spot/trade/precision", params={"symbol": symbol})

    async def get_spot_pair_klines(
        self, symbol: str, interval: str = "1h", limit: int = 200,
    ) -> BybitResponse:
        """Get spot kline/candlestick data."""
        return await self.get(
            "/v3/public/spot/market/kline",
            params={"symbol": symbol, "interval": interval, "limit": str(limit)},
        )

    async def get_order_book(self, symbol: str, limit: int = 25) -> BybitResponse:
        """Get order book depth."""
        return await self.get(
            "/v3/public/spot/market/orderbook",
            params={"symbol": symbol, "limit": str(limit)},
        )

    async def get_instruments_info(self, category: str = "spot") -> BybitResponse:
        """Get instruments info by category (spot, linear, inverse)."""
        return await self.get(
            "/v5/market/instruments-info",
            params={"category": category},
        )

    async def get_linear_instruments_info(self) -> BybitResponse:
        """Get linear perpetual instruments info."""
        return await self.get_instruments_info("linear")

    async def get_trading_coins(self) -> BybitResponse:
        """Get available trading coins list."""
        return await self.get("/v3/public/spot/trade/coins")

    # ================================================================
    # CONTRACT / DERIVATIVES
    # ================================================================

    def _get_contract_request_params(
        self, symbol: str, interval: str, limit: int,
        contract_type: str = "linear",
    ) -> Dict[str, str]:
        """Build params for contract kline requests."""
        return {
            "category": contract_type,
            "symbol": symbol,
            "interval": interval,
            "limit": str(limit),
        }

    async def _get_contract_coin_kline_price_history(
        self,
        symbol: str,
        interval: str = "60",
        limit: int = 200,
        kline_type: str = "market",
        contract_type: str = "linear",
    ) -> BybitResponse:
        """Get contract kline data (market or mark price)."""
        endpoint = "/v5/market/kline" if kline_type == "market" else "/v5/market/mark-price-kline"
        params = self._get_contract_request_params(symbol, interval, limit, contract_type)
        return await self.get(endpoint, params=params)

    async def get_contract_coin_market_kline_price_history(
        self, symbol: str, interval: str = "60", limit: int = 200,
    ) -> BybitResponse:
        return await self._get_contract_coin_kline_price_history(
            symbol, interval, limit, "market",
        )

    async def get_contract_coin_mark_kline_price_history(
        self, symbol: str, interval: str = "60", limit: int = 200,
    ) -> BybitResponse:
        return await self._get_contract_coin_kline_price_history(
            symbol, interval, limit, "mark",
        )

    async def show_contract_order(self, symbol: str, order_id: str) -> BybitResponse:
        """Get contract order details."""
        return await self.get(
            "/v5/order/realtime",
            params={"category": "linear", "symbol": symbol, "orderId": order_id},
        )

    async def get_contract_pairs(self) -> BybitResponse:
        """Get all contract pairs."""
        return await self.get("/v5/market/instruments-info", params={"category": "linear"})

    # ================================================================
    # COUNTRIES / PERMISSIONS
    # ================================================================

    async def get_countries(self) -> BybitResponse:
        """Get list of supported countries."""
        return await self.get("/v3/public/countries")

    async def get_permission(self) -> BybitResponse:
        """Get account permissions for current region."""
        return await self.get("/register/permission_v2")

    async def check_ref_code(self, ref_code: str) -> BybitResponse:
        """Check if a referral code is valid."""
        return await self.get(
            "/s1/campaign/referral/commission/check-ref-code",
            params={"refCode": ref_code},
        )

    # ================================================================
    # TOKENSPLASH
    # ================================================================

    async def get_tokensplash(self, code: int) -> BybitResponse:
        return await self.get("/segw/tokensplash/v1/detail", params={"code": str(code)})

    async def get_tokensplash_list(self) -> BybitResponse:
        return await self.get("/segw/tokensplash/v1/list")

    async def get_ended_tokensplash_list(self) -> BybitResponse:
        return await self.get("/segw/tokensplash/v1/ended-list")

    # ================================================================
    # PUZZLEHUNT
    # ================================================================

    async def get_puzzlehunt_activity(self, code: int) -> BybitResponse:
        return await self.get("/segw/puzzle/v1/activity", params={"code": str(code)})

    async def get_puzzlehunt_activity_list(self) -> BybitResponse:
        return await self.get("/segw/puzzle/v1/activity/list")

    async def get_puzzlehunt_campaign_guaranteed_prize(self, code: int) -> BybitResponse:
        return await self.get(
            "/segw/puzzle/v1/campaign/guaranteed-prize",
            params={"code": str(code)},
        )

    # ================================================================
    # LAUNCHPOOL
    # ================================================================

    async def get_launchpool_list(self) -> BybitResponse:
        return await self.get("/segw/launchpool/v1/list")

    # ================================================================
    # EARN (ByFi)
    # ================================================================

    async def earn_get_coins(self) -> BybitResponse:
        return await self.get("/v3/public/byfi/coins")

    async def earn_get_product_cards(self, coin: str = "USDT") -> BybitResponse:
        return await self.get("/v3/public/byfi/product-cards", params={"coin": coin})

    async def earn_get_product_detail(self, product_id: str) -> BybitResponse:
        return await self.get("/v3/public/byfi/product-detail", params={"productId": product_id})

    # ================================================================
    # MT5
    # ================================================================

    async def mt5_get_symbol_list(self) -> BybitResponse:
        return await self.get("/v3/public/mt5/symbol-list")

    # ================================================================
    # PROJECT KEY INFO
    # ================================================================

    async def get_project_key_info(self, project_id: str) -> BybitResponse:
        return await self.get("/v3/public/project/key-info", params={"projectId": project_id})

    # ================================================================
    # WEB3
    # ================================================================

    async def web3_get_chains(self) -> BybitResponse:
        return await self.get("/web3/v1/public/chains")

    async def web3_get_supported_chain(self) -> BybitResponse:
        return await self.get("/web3/v1/public/supported-chains")

    async def web3_get_activity(self, code: int) -> BybitResponse:
        return await self.get("/web3/v1/public/activity", params={"code": str(code)})

    async def web3_get_airdrop_arcade_list(self) -> BybitResponse:
        return await self.get("/web3/v1/public/airdrop-arcade/list")

    async def web3_get_daily_airdrop_list(self) -> BybitResponse:
        return await self.get("/web3/v1/public/daily-airdrop/list")

    async def web3_get_featured_airdrop_list(self) -> BybitResponse:
        return await self.get("/web3/v1/public/featured-airdrop/list")

    async def web3_get_wallets_balance_usd(self, wallet_ids: str = "") -> BybitResponse:
        params = {}
        if wallet_ids:
            params["walletIds"] = wallet_ids
        return await self.get("/web3/v1/public/wallets/balance-usd", params=params)

    async def web3_get_mnemonic_phrase_wallets(self) -> BybitResponse:
        return await self.get("/web3/v1/public/mnemonic-wallet/list")

    async def web3_get_mnemonic_phrase_wallet_tokens(self, wallet_id: str) -> BybitResponse:
        return await self.get(
            "/web3/v1/public/mnemonic-wallet/tokens",
            params={"walletId": wallet_id},
        )

    async def web3_register_mnemonic_phrase_wallet(self, mnemonic: str, name: str = "") -> BybitResponse:
        return await self.post(
            "/web3/v1/public/mnemonic-wallet/register",
            json_data={"mnemonic": mnemonic, "walletName": name},
        )

    async def web3_get_withdraw_gas_fee_v2(self, chain_id: str, coin: str) -> BybitResponse:
        return await self.get(
            "/web3/v1/public/withdraw/gas-fee-v2",
            params={"chainId": chain_id, "coin": coin},
        )
