"""
Bybit PrivateClient — recovered from Nuitka binary + memory dump.

Extends BasePrivateClient with higher-level logic:
- Captcha solving (delegates to anycaptcha)
- Email code retrieval (delegates to IMAP)
- Login flow with risk token verification
- Withdraw flow with risk token + 2FA
- 2FA enable/disable with full flow
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from .base import (
    BybitComponentError,
    BybitDevice,
    BybitException,
    BybitHTTPJSONException,
    BybitResponse,
)
from .base_private_client import BasePrivateClient

logger = logging.getLogger("bybit.client.private")


class PrivateClient(BasePrivateClient):
    """
    Full-featured Bybit private client with captcha solving and email integration.

    This is the main client class used by the manager. It wraps BasePrivateClient
    methods with full login/verification flows including:
    - Automatic captcha solving via anycaptcha (capmonster, 2captcha, etc.)
    - Email code retrieval via IMAP
    - Risk token verification with 2FA fallback
    """

    def __init__(
        self,
        email: str = "",
        password: str = "",
        totp_secret: str = "",
        payment_password: str = "",
        proxy: Optional[str] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        device: Optional[BybitDevice] = None,
        base_url: str = "https://api2.bybitglobal.com",
        locale: str = "en",
        country_code: str = "",
        captcha_solver: Optional[Any] = None,
        email_client: Optional[Any] = None,
    ):
        super().__init__(
            email=email,
            password=password,
            totp_secret=totp_secret,
            payment_password=payment_password,
            proxy=proxy,
            cookies=cookies,
            device=device,
            base_url=base_url,
            locale=locale,
            country_code=country_code,
        )
        self.captcha_solver = captcha_solver  # anycaptcha solver instance
        self.email_client = email_client  # IMAP email client for code retrieval

    # ================================================================
    # CAPTCHA SOLVING
    # ================================================================

    async def _solve_and_verify_captcha(self, scene: str = "31000") -> Dict[str, Any]:
        """
        Full captcha flow:
        1. Request captcha order from Bybit (get serial_no / token)
        2. Solve via external service (capmonster, 2captcha, etc.)
        3. Verify solution with Bybit
        4. Return captcha verification data for use in subsequent requests
        """
        if not self.captcha_solver:
            raise BybitException(ret_code=-1, ret_msg="No captcha solver configured")

        from .base import RECAPTCHA_SITE_KEY

        # Step 1: Get captcha order
        order_resp = await self.get_captcha(scene=scene)
        order_data = order_resp.result or {}

        captcha_type = order_data.get("captcha_type", "recaptcha")
        serial_no = order_data.get("serial_no", "")
        token = order_data.get("token", "")
        site_key = order_data.get("site_key", RECAPTCHA_SITE_KEY)
        page_url = order_data.get("page_url", "https://bybitglobal.com")

        # The order response returns a token, not serial_no
        if not serial_no and token:
            serial_no = token

        if not serial_no:
            raise BybitException(ret_code=-1, ret_msg="No serial_no/token in captcha order")

        # Step 2: Solve captcha
        if captcha_type == "recaptcha":
            solution = await self._solve_recaptcha_v2(site_key, page_url)
        elif captcha_type == "geetest_v4":
            solution = await self._solve_geetest_v4(
                captcha_id=order_data.get("captcha_id", ""),
            )
        elif captcha_type == "geetest":
            solution = await self._solve_geetest(
                gt=order_data.get("gt", ""),
                challenge=order_data.get("challenge", ""),
                page_url=page_url,
            )
        else:
            raise BybitException(
                ret_code=-1,
                ret_msg=f"Unsupported captcha type: {captcha_type}",
            )

        # Step 3: Verify with Bybit
        verify_resp = await self._verify_captcha(
            serial_no=serial_no,
            captcha_type=captcha_type,
            captcha_response=solution,
            scene=scene,
        )

        return {
            "captcha_type": captcha_type,
            "serial_no": serial_no,
            "captcha_response": solution,
            "verify_result": verify_resp.result,
        }

    async def _dummy_solve_and_verify_captcha(self, scene: str = "31000") -> Dict[str, Any]:
        """Dummy captcha solver for testing — returns empty data."""
        return {"captcha_type": "none", "serial_no": "", "captcha_response": ""}

    async def _solve_recaptcha_v2(self, site_key: str, page_url: str) -> str:
        """Solve reCAPTCHA v2 using the configured captcha service."""
        if not self.captcha_solver:
            raise BybitException(ret_code=-1, ret_msg="No captcha solver")

        from anycaptcha.captcha.recaptcha_v2 import RecaptchaV2

        task = RecaptchaV2(
            site_key=site_key,
            page_url=page_url,
            proxy=self.proxy,
        )
        result = await self.captcha_solver.solve(task)
        return result.solution.get("gRecaptchaResponse", "")

    async def _solve_geetest(self, gt: str, challenge: str, page_url: str) -> str:
        """Solve GeeTest v3 captcha."""
        if not self.captcha_solver:
            raise BybitException(ret_code=-1, ret_msg="No captcha solver")

        from anycaptcha.captcha.geetest import GeeTest

        task = GeeTest(
            gt=gt,
            challenge=challenge,
            page_url=page_url,
            proxy=self.proxy,
        )
        result = await self.captcha_solver.solve(task)
        return json.dumps(result.solution)

    async def _solve_geetest_v4(self, captcha_id: str, **kwargs) -> str:
        """Solve GeeTest v4 captcha."""
        if not self.captcha_solver:
            raise BybitException(ret_code=-1, ret_msg="No captcha solver")

        from anycaptcha.captcha.geetest_v4 import GeeTestV4

        task = GeeTestV4(
            captcha_id=captcha_id,
            page_url="https://bybitglobal.com",
            proxy=self.proxy,
        )
        result = await self.captcha_solver.solve(task)
        return json.dumps(result.solution)

    # ================================================================
    # EMAIL CODE RETRIEVAL
    # ================================================================

    async def _wait_for_email_code(
        self,
        email: str = "",
        subject_filter: str = "Bybit",
        timeout: int = 120,
        poll_interval: int = 5,
    ) -> str:
        """
        Wait for an email code from Bybit via IMAP.
        Polls the inbox for a matching email and extracts the verification code.
        """
        if not self.email_client:
            raise BybitException(ret_code=-1, ret_msg="No email client configured")

        email = email or self.email
        start = asyncio.get_event_loop().time()

        while (asyncio.get_event_loop().time() - start) < timeout:
            try:
                code = await self.email_client.get_verification_code(
                    email=email,
                    subject_filter=subject_filter,
                )
                if code:
                    return code
            except Exception as e:
                logger.debug("Email poll failed: %s", e)

            await asyncio.sleep(poll_interval)

        raise BybitException(
            ret_code=-1,
            ret_msg=f"Timeout waiting for email code ({timeout}s)",
        )

    async def _get_register_email_code(self, email: str = "") -> str:
        """Send registration email code and wait for it."""
        await self.send_email_code_to_register(email or self.email)
        return await self._wait_for_email_code(
            email or self.email,
            subject_filter="verification",
        )

    async def _get_risk_token_email_code(self, risk_token: str) -> str:
        """Send risk token email code and wait for it."""
        await self.send_email_code_to_verify_risk_token(risk_token)
        return await self._wait_for_email_code(
            self.email,
            subject_filter="verification",
        )

    # ================================================================
    # LOGIN FLOW
    # ================================================================

    async def login_logic(
        self,
        solve_captcha: bool = True,
        use_totp: bool = True,
    ) -> BybitResponse:
        """
        Full login flow with automatic captcha solving and 2FA handling.

        1. Solve captcha to get verification token
        2. Attempt login with captcha token + RSA-encrypted password
        3. If 2FA required → get risk components, verify with TOTP
        4. Update cookies on success
        """
        await self._init_missing_cookies()

        # Step 1: Solve captcha first (required for login)
        captcha_token = ""
        if solve_captcha and self.captcha_solver:
            try:
                captcha_data = await self._solve_and_verify_captcha(scene="31000")
                captcha_token = captcha_data.get("verify_result", {}).get(
                    "token", captcha_data.get("serial_no", "")
                )
            except Exception as captcha_err:
                logger.warning("Captcha solving failed: %s", captcha_err)

        try:
            # Step 2: Login with captcha token
            totp_code = ""
            if use_totp and self.totp_secret:
                totp_code = await self.wait_totp_code()

            resp = await self.direct_login(
                totp_code=totp_code,
                captcha_token=captcha_token,
            )
            return resp

        except BybitComponentError as e:
            logger.info("Login requires verification: %s", e.ret_msg)

            # Verify risk token with 2FA
            return await self._verify_challenge_risk_token_logic(
                risk_token=e.risk_token,
                challenges=e.challenges,
                captcha_data={},
            )

    async def login_and_verify_risk_token(
        self,
        risk_token: str = "",
        captcha_data: Optional[Dict] = None,
    ) -> BybitResponse:
        """Login and verify risk token in one step."""
        if not risk_token:
            return await self.login_logic()
        return await self._verify_challenge_risk_token_logic(
            risk_token=risk_token,
            captcha_data=captcha_data or {},
        )

    async def _verify_challenge_risk_token_logic(
        self,
        risk_token: str,
        challenges: Optional[List[Dict]] = None,
        captcha_data: Optional[Dict] = None,
    ) -> BybitResponse:
        """
        Handle risk token verification challenges.
        May require: TOTP code, email code, or both.
        """
        totp_code = ""
        email_code = ""

        # Check what verification is needed
        challenge_types = set()
        for ch in (challenges or []):
            challenge_types.add(ch.get("type", ""))

        if "totp" in challenge_types or "google2fa" in challenge_types:
            if self.totp_secret:
                totp_code = await self.wait_totp_code()
            else:
                raise BybitException(
                    ret_code=-1,
                    ret_msg="TOTP required but no secret available",
                )

        if "email" in challenge_types:
            email_code = await self._get_risk_token_email_code(risk_token)

        return await self.verify_risk_token(
            risk_token=risk_token,
            totp_code=totp_code,
            email_code=email_code,
        )

    async def _get_risk_token_with_relogin(self, scenario: str) -> str:
        """Get risk token, re-logging in if session expired."""
        try:
            resp = await self._get_risk_token(scenario)
            return resp.result.get("risk_token", "") if resp.result else ""
        except BybitHTTPJSONException as e:
            if e.ret_code in (20001, 10005):  # not logged in / permission denied
                await self.login_logic()
                resp = await self._get_risk_token(scenario)
                return resp.result.get("risk_token", "") if resp.result else ""
            raise

    # ================================================================
    # VERIFY RISK TOKEN LOGIC
    # ================================================================

    async def verify_risk_token_logic(
        self,
        risk_token: str,
        use_totp: bool = True,
        use_email: bool = False,
    ) -> BybitResponse:
        """Verify risk token with TOTP and/or email code."""
        totp_code = ""
        email_code = ""

        if use_totp and self.totp_secret:
            totp_code = await self.wait_totp_code()

        if use_email and self.email_client:
            email_code = await self._get_risk_token_email_code(risk_token)

        return await self.verify_risk_token(
            risk_token=risk_token,
            totp_code=totp_code,
            email_code=email_code,
        )

    async def verify_risk_token_to_change_email(
        self, risk_token: str,
    ) -> BybitResponse:
        """Verify risk token specifically for email change."""
        return await self.verify_risk_token_logic(
            risk_token, use_totp=True, use_email=True,
        )

    # ================================================================
    # RISK TOKEN GETTERS
    # ================================================================

    async def get_risk_token_to_register(self) -> str:
        """Get risk token for registration flow."""
        resp = await self._get_risk_token("register")
        return resp.result.get("risk_token", "") if resp.result else ""

    async def get_risk_token_to_add_withdraw_address(self) -> str:
        """Get risk token for adding a withdraw address."""
        return await self._get_risk_token_with_relogin("add_withdraw_address")

    async def get_risk_token_to_switch_withdraw_address_verification(self) -> str:
        """Get risk token for toggling withdraw address whitelist."""
        return await self._get_risk_token_with_relogin("switch_withdraw_address_verification")

    # ================================================================
    # WITHDRAW FLOW
    # ================================================================

    async def withdraw_logic(
        self,
        coin: str,
        chain: str,
        address: str,
        amount: float,
        use_totp: bool = True,
    ) -> BybitResponse:
        """
        Full withdrawal flow:
        1. Get risk token for withdrawal
        2. Verify risk token with 2FA
        3. Execute on-chain withdrawal
        """
        # Step 1: Get risk token
        risk_resp = await self.get_risk_token_to_withdraw(
            coin=coin, amount=amount, address=address, chain=chain,
        )
        risk_token = ""
        if risk_resp.result and isinstance(risk_resp.result, dict):
            risk_token = risk_resp.result.get("riskToken", risk_resp.result.get("risk_token", ""))

        # Step 2: Verify risk token
        totp_code = ""
        if use_totp and self.totp_secret:
            totp_code = await self.wait_totp_code()

        if risk_token:
            await self.verify_risk_token(
                risk_token=risk_token,
                totp_code=totp_code,
            )

        # Step 3: Execute withdrawal
        return await self.onchain_withdraw(
            coin=coin,
            chain=chain,
            address=address,
            amount=amount,
            risk_token=risk_token,
            totp_code=totp_code,
            payment_password=self.payment_password,
        )

    # ================================================================
    # WITHDRAW ADDRESS FLOW
    # ================================================================

    async def add_withdraw_address_logic(
        self,
        coin: str,
        chain: str,
        address: str,
        remark: str = "",
    ) -> BybitResponse:
        """
        Full add withdraw address flow with risk token verification.
        """
        risk_token = await self.get_risk_token_to_add_withdraw_address()
        totp_code = ""
        if self.totp_secret:
            totp_code = await self.wait_totp_code()

        if risk_token:
            await self.verify_risk_token(
                risk_token=risk_token,
                totp_code=totp_code,
            )

        return await self.add_withdraw_address(
            coin=coin,
            chain=chain,
            address=address,
            remark=remark,
            risk_token=risk_token,
            totp_code=totp_code,
        )

    async def switch_withdraw_address_verification(self, enable: bool = True) -> BybitResponse:
        """Toggle withdraw address whitelist with full verification."""
        risk_token = await self.get_risk_token_to_switch_withdraw_address_verification()
        totp_code = ""
        if self.totp_secret:
            totp_code = await self.wait_totp_code()
        if risk_token:
            await self.verify_risk_token(risk_token=risk_token, totp_code=totp_code)
        return await self._switch_withdraw_address_verification(
            enable=enable, risk_token=risk_token, totp_code=totp_code,
        )

    # ================================================================
    # 2FA FLOWS
    # ================================================================

    async def generate_and_enable_2fa_logic(self) -> Tuple[str, str]:
        """Full flow to generate and enable 2FA with risk verification."""
        risk_token = await self._get_risk_token_with_relogin("enable_2fa")
        if risk_token:
            await self.verify_risk_token_logic(risk_token, use_totp=False, use_email=True)
        return await self.generate_and_enable_2fa(risk_token=risk_token)

    async def disable_unknown_2fa_logic(self, risk_token: str = "") -> BybitResponse:
        """Disable 2FA when the TOTP secret is unknown."""
        if not risk_token:
            risk_token = await self._get_risk_token_with_relogin("disable_2fa")

        email_code = await self._get_risk_token_email_code(risk_token)
        return await self.disable_unknown_2fa(
            risk_token=risk_token,
            email_code=email_code,
        )

    # ================================================================
    # ENABLE FEATURES
    # ================================================================

    async def enable_payment_password_logic(self, password: str = "") -> BybitResponse:
        """Enable payment password with risk verification."""
        risk_token = await self._get_risk_token_with_relogin("enable_payment_password")
        if risk_token:
            await self.verify_risk_token_logic(risk_token)
        return await self.enable_payment_password(
            password=password or self.payment_password,
            risk_token=risk_token,
        )

    async def enable_withdraw_whitelist_logic(self) -> BybitResponse:
        """Enable withdraw whitelist with risk verification."""
        risk_token = await self.get_risk_token_to_switch_withdraw_address_verification()
        if risk_token:
            await self.verify_risk_token_logic(risk_token)
        return await self.enable_withdraw_whitelist(risk_token=risk_token)

    async def reset_password_logic(
        self, new_password: str, email: str = "",
    ) -> BybitResponse:
        """Full password reset flow."""
        risk_token = await self._get_risk_token_with_relogin("reset_password")
        email_code = await self._get_risk_token_email_code(risk_token)
        return await self.reset_password(
            email=email or self.email,
            new_password=new_password,
            email_code=email_code,
            risk_token=risk_token,
        )

    # ================================================================
    # API KEY
    # ================================================================

    async def generate_api_key(
        self, note: str = "", permissions: Optional[Dict] = None,
    ) -> BybitResponse:
        """Generate API key with risk verification."""
        risk_token = await self._get_risk_token_with_relogin("generate_api_key")
        totp_code = ""
        if self.totp_secret:
            totp_code = await self.wait_totp_code()
        if risk_token:
            await self.verify_risk_token(risk_token=risk_token, totp_code=totp_code)
        return await self._generate_api_key(
            note=note, permissions=permissions,
            risk_token=risk_token, totp_code=totp_code,
        )

    # ================================================================
    # KYC
    # ================================================================

    async def get_kyc_identity(self) -> BybitResponse:
        """Get KYC identity info (wraps _get_kyc_identity)."""
        return await self._get_kyc_identity()

    async def get_referral_code(self) -> str:
        """Get referral code as string."""
        resp = await super().get_referral_code()
        if resp.result and isinstance(resp.result, dict):
            return resp.result.get("referral_code", resp.result.get("ref_code", ""))
        return ""

    # ================================================================
    # WEB3 ETH
    # ================================================================

    async def web3_sign_tx(self, **kwargs) -> BybitResponse:
        return await self._web3_sign_tx(**kwargs)

    async def web3_eth_sign_tx(self, **kwargs) -> BybitResponse:
        return await self._web3_sign_eth_tx(**kwargs)

    async def _web3_eth_withdraw(
        self, wallet_id: str, chain_id: str, to_address: str,
        amount: str, token_address: str = "",
    ) -> BybitResponse:
        """Withdraw from web3 wallet."""
        broadcast_data = await self.web3_get_broadcast_data(
            walletId=wallet_id,
            chainId=chain_id,
            toAddress=to_address,
            amount=amount,
            tokenAddress=token_address,
        )
        # Sign and broadcast
        tx_data = broadcast_data.result
        signed = await self._web3_sign_eth_tx(**tx_data)
        return signed

    async def web3_eth_withdraw_native_currency(
        self, wallet_id: str, chain_id: str, to_address: str, amount: str,
    ) -> BybitResponse:
        return await self._web3_eth_withdraw(
            wallet_id=wallet_id, chain_id=chain_id,
            to_address=to_address, amount=amount,
        )

    async def web3_eth_withdraw_token(
        self, wallet_id: str, chain_id: str, to_address: str,
        amount: str, token_address: str,
    ) -> BybitResponse:
        return await self._web3_eth_withdraw(
            wallet_id=wallet_id, chain_id=chain_id,
            to_address=to_address, amount=amount,
            token_address=token_address,
        )

    async def web3_join_ido(self, code: int) -> BybitResponse:
        """Join web3 IDO with full flow."""
        # Check registration status first
        status = await self.web3_get_ido_registration_status(code)
        if status.result and status.result.get("registered"):
            return status
        return await super().web3_join_ido(code)

    # ================================================================
    # DIRECT REQUEST (override)
    # ================================================================

    async def direct_request(
        self,
        method: str,
        url: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> BybitResponse:
        """Make direct request, re-login on auth failure."""
        try:
            return await super().direct_request(method, url, json_data=json_data, params=params)
        except BybitHTTPJSONException as e:
            if e.ret_code in (20001, 10005):
                await self.login_logic(solve_captcha=True)
                return await super().direct_request(method, url, json_data=json_data, params=params)
            raise
