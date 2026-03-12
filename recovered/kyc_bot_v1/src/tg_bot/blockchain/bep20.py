"""
BEP20 USDT client for partner payouts.

From memory:
  Bep20USDTClient.__init__
  Bep20USDTClient.decimals
  Bep20USDTClient.send_usdt
  Bep20USDTClient.to_wei
  Bep20USDTClient.validate_address
  BSC_RPC_URL
  Usage: /set_wallet USDT BSC(BEP20) address
  File "...\\tg_bot\\blockchain\\bep20.py", line 61, in send_usdt
  web3.exceptions.ContractLogicError: 'BEP20: transfer amount exceeds balance'
"""
from __future__ import annotations

import logging
from typing import Optional

from web3 import Web3
from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)

# BSC Mainnet RPC
BSC_RPC_URL = "https://bsc-dataseed1.binance.org"

# USDT BEP20 contract on BSC
USDT_CONTRACT_ADDRESS = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")

# Standard BEP20 ABI (transfer + balanceOf + decimals)
USDT_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
]


class Bep20USDTClient:
    """
    Client for sending USDT on BSC (BEP20) for partner payouts.

    Requires a funded BSC wallet private key in config.
    """

    def __init__(self, private_key: str, rpc_url: str = BSC_RPC_URL) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.private_key = private_key
        self.account = self.w3.eth.account.from_key(private_key)
        self.contract = self.w3.eth.contract(
            address=USDT_CONTRACT_ADDRESS,
            abi=USDT_ABI,
        )
        self._decimals: Optional[int] = None

    @property
    def decimals(self) -> int:
        """Get USDT token decimals (18 for BSC USDT)."""
        if self._decimals is None:
            self._decimals = self.contract.functions.decimals().call()
        return self._decimals

    def to_wei(self, amount: float) -> int:
        """Convert human-readable USDT amount to wei."""
        return int(amount * (10 ** self.decimals))

    @staticmethod
    def validate_address(address: str) -> bool:
        """Validate a BSC/ETH address."""
        return Web3.is_address(address)

    def send_usdt(self, to_address: str, amount: float) -> str:
        """
        Send USDT to the specified address.

        Args:
            to_address: Recipient BSC address.
            amount: Amount in USDT (human readable, e.g. 5.0).

        Returns:
            Transaction hash as hex string.

        Raises:
            ValueError: If address is invalid.
            web3.exceptions.ContractLogicError: If insufficient balance.
        """
        if not self.validate_address(to_address):
            raise ValueError(f"Invalid BSC address: {to_address}")

        to_checksum = Web3.to_checksum_address(to_address)
        amount_wei = self.to_wei(amount)

        # Build transaction
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = self.contract.functions.transfer(
            to_checksum, amount_wei
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": 100000,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": 56,  # BSC mainnet
        })

        # Sign and send
        signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)

        logger.info(
            "Sent %.4f USDT to %s, tx: %s",
            amount, to_address, tx_hash.hex(),
        )
        return tx_hash.hex()
