"""
Bybit Manager — orchestrates all operations across multiple accounts.

Central coordinator that ties together:
- Database (account CRUD, state persistence)
- Client pool (Bybit API clients per account)
- Config (captcha services, proxies, email providers)
- Bulk operations (login, withdraw, check balance, etc.)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bybit.client import BybitException, BybitDevice
from bybit_manager.client import ClientPool, ManagedClient
from bybit_manager.config import Config
from bybit_manager.database.database import Database
from bybit_manager.database.models import (
    BybitAccount, Email, FinanceAccount,
    DepositAddress, DepositHistory,
    WithdrawAddress, WithdrawHistory,
    Award, AirdropHunt, TokenSplash, PuzzleHunt, IDO,
    Web3Wallet, Web3Chain, Web3Token,
)

logger = logging.getLogger("bybit_manager.manager")


class Manager:
    """Central manager orchestrating all Bybit account operations."""

    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config.database_url)
        self.client_pool = ClientPool(config)

    async def init(self) -> None:
        """Initialize database and connection pools."""
        await self.db.create_tables()
        logger.info("Manager initialized, database tables ready")

    async def shutdown(self) -> None:
        """Graceful shutdown — close all clients and DB connections."""
        await self.client_pool.close_all()
        await self.db.close()
        logger.info("Manager shutdown complete")

    # ================================================================
    # Account CRUD
    # ================================================================

    async def get_accounts(
        self,
        group_name: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[BybitAccount], int]:
        """Get paginated account list with optional group filter."""
        async with self.db.session() as session:
            query = select(BybitAccount)
            if group_name:
                query = query.where(BybitAccount.group_name == group_name)

            # Count total
            from sqlalchemy import func
            count_q = select(func.count()).select_from(query.subquery())
            total = (await session.execute(count_q)).scalar() or 0

            # Paginate
            query = query.offset((page - 1) * page_size).limit(page_size)
            result = await session.execute(query)
            accounts = list(result.scalars().all())

            return accounts, total

    async def get_account(self, database_id: int) -> Optional[BybitAccount]:
        """Get single account by database_id."""
        async with self.db.session() as session:
            result = await session.execute(
                select(BybitAccount).where(
                    BybitAccount.database_id == database_id
                )
            )
            return result.scalar_one_or_none()

    async def create_account(
        self,
        email_address: str,
        password: Optional[str] = None,
        group_name: str = "no_group",
        imap_address: Optional[str] = None,
        imap_password: Optional[str] = None,
        proxy: Optional[str] = None,
        **kwargs,
    ) -> BybitAccount:
        """Create a new account with email record."""
        async with self.db.session() as session:
            # Ensure email record exists
            email_obj = await session.get(Email, email_address)
            if not email_obj:
                email_obj = Email(
                    address=email_address,
                    imap_address=imap_address,
                    imap_password=imap_password,
                )
                session.add(email_obj)

            account = BybitAccount(
                email_address=email_address,
                password=password,
                group_name=group_name,
                proxy=proxy,
                **kwargs,
            )
            session.add(account)
            await session.commit()
            await session.refresh(account)
            logger.info("Created account %d for %s", account.database_id, email_address)
            return account

    async def update_account(
        self,
        database_id: int,
        **fields,
    ) -> Optional[BybitAccount]:
        """Update account fields."""
        async with self.db.session() as session:
            account = await session.get(BybitAccount, database_id)
            if not account:
                return None

            for key, value in fields.items():
                if value is not None and hasattr(account, key):
                    setattr(account, key, value)

            await session.commit()
            await session.refresh(account)
            return account

    async def delete_accounts(self, database_ids: List[int]) -> int:
        """Delete accounts by database_ids. Returns count deleted."""
        async with self.db.session() as session:
            from sqlalchemy import delete as sa_delete
            result = await session.execute(
                sa_delete(BybitAccount).where(
                    BybitAccount.database_id.in_(database_ids)
                )
            )
            await session.commit()
            return result.rowcount

    # ================================================================
    # Client management
    # ================================================================

    async def get_client(self, database_id: int) -> ManagedClient:
        """Get or create a ManagedClient for an account."""
        account = await self.get_account(database_id)
        if not account:
            raise ValueError(f"Account {database_id} not found")

        # Get email info for IMAP
        async with self.db.session() as session:
            email_obj = await session.get(Email, account.email_address)

        return self.client_pool.get_or_create(
            database_id=database_id,
            email_address=account.email_address,
            password=account.password,
            totp_secret=account.totp_secret,
            proxy=account.proxy,
            cookies=account.cookies,
            preferred_country_code=account.preferred_country_code,
            chrome_major_version=account.chrome_major_version,
            os_name=account.os,
            screen_width=account.screen_width,
            screen_height=account.screen_height,
            imap_address=email_obj.imap_address if email_obj else None,
            imap_password=email_obj.imap_password if email_obj else None,
            email_client_id=email_obj.client_id if email_obj else None,
            email_refresh_token=email_obj.refresh_token if email_obj else None,
        )

    # ================================================================
    # Bulk operations
    # ================================================================

    async def bulk_login(
        self,
        database_ids: List[int],
        concurrency: int = 5,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Login multiple accounts concurrently."""
        sem = asyncio.Semaphore(concurrency)
        results = {"success": [], "failed": []}

        async def _login_one(db_id: int):
            async with sem:
                try:
                    client = await self.get_client(db_id)
                    result = await client.login()
                    # Persist cookies
                    await self.update_account(
                        db_id,
                        cookies=client.cookies,
                        registered=True,
                    )
                    results["success"].append({
                        "database_id": db_id,
                        "uid": result.get("uid"),
                        "status": "logged_in",
                    })
                except Exception as e:
                    logger.error("Login failed for %d: %s", db_id, e)
                    results["failed"].append({
                        "database_id": db_id,
                        "error": str(e),
                    })

        await asyncio.gather(*[_login_one(db_id) for db_id in database_ids])
        return results

    async def bulk_check_balance(
        self,
        database_ids: List[int],
        concurrency: int = 10,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Check balances for multiple accounts."""
        sem = asyncio.Semaphore(concurrency)
        results = {"success": [], "failed": []}

        async def _check_one(db_id: int):
            async with sem:
                try:
                    client = await self.get_client(db_id)
                    balance = await client.client.get_total_usd_balance()
                    await self.update_account(db_id, balance_usd=balance)
                    results["success"].append({
                        "database_id": db_id,
                        "balance_usd": balance,
                    })
                except Exception as e:
                    results["failed"].append({
                        "database_id": db_id,
                        "error": str(e),
                    })

        await asyncio.gather(*[_check_one(db_id) for db_id in database_ids])
        return results

    async def bulk_withdraw(
        self,
        database_ids: List[int],
        coin: str,
        chain: str,
        address: str,
        amount: float,
        withdraw_type: int = 0,
        concurrency: int = 3,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Execute withdrawal for multiple accounts."""
        sem = asyncio.Semaphore(concurrency)
        results = {"success": [], "failed": []}

        async def _withdraw_one(db_id: int):
            async with sem:
                try:
                    client = await self.get_client(db_id)
                    result = await client.withdraw(
                        coin=coin,
                        chain=chain,
                        address=address,
                        amount=amount,
                        withdraw_type=withdraw_type,
                    )
                    results["success"].append({
                        "database_id": db_id,
                        "status": "submitted",
                        **result,
                    })
                except Exception as e:
                    logger.error("Withdraw failed for %d: %s", db_id, e)
                    results["failed"].append({
                        "database_id": db_id,
                        "error": str(e),
                    })

        await asyncio.gather(*[_withdraw_one(db_id) for db_id in database_ids])
        return results

    async def bulk_get_profile(
        self,
        database_ids: List[int],
        concurrency: int = 10,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch and update profile info for multiple accounts."""
        sem = asyncio.Semaphore(concurrency)
        results = {"success": [], "failed": []}

        async def _profile_one(db_id: int):
            async with sem:
                try:
                    client = await self.get_client(db_id)
                    profile = await client.client.get_profile()
                    # Update account with profile data
                    await self.update_account(
                        db_id,
                        uid=profile.get("id"),
                        email_verified=profile.get("email_verified"),
                        totp_enabled=profile.get("has_google2fa"),
                        is_uta=profile.get("is_uta"),
                    )
                    results["success"].append({
                        "database_id": db_id,
                        "profile": profile,
                    })
                except Exception as e:
                    results["failed"].append({
                        "database_id": db_id,
                        "error": str(e),
                    })

        await asyncio.gather(*[_profile_one(db_id) for db_id in database_ids])
        return results

    async def sync_finance_accounts(
        self,
        database_id: int,
    ) -> List[Dict[str, Any]]:
        """Fetch and sync all finance account balances for an account."""
        client = await self.get_client(database_id)
        balances = await client.client.get_finance_account_balances()

        async with self.db.session() as session:
            account = await session.get(BybitAccount, database_id)
            if not account or not account.uid:
                raise ValueError(f"Account {database_id} has no uid")

            from bybit_manager.database.models.finance_account import (
                FinanceAccountType,
            )
            from sqlalchemy import delete as sa_delete

            # Clear old records
            await session.execute(
                sa_delete(FinanceAccount).where(
                    FinanceAccount.uid == account.uid
                )
            )

            # Insert new
            records = []
            for bal in balances:
                try:
                    acct_type = FinanceAccountType(bal["type"])
                except (ValueError, KeyError):
                    continue

                fa = FinanceAccount(
                    uid=account.uid,
                    type=acct_type,
                    balance=bal.get("balance", 0.0),
                )
                session.add(fa)
                records.append({
                    "type": acct_type.value,
                    "balance": bal.get("balance", 0.0),
                })

            await session.commit()

        return records

    async def sync_deposit_history(
        self,
        database_id: int,
    ) -> int:
        """Fetch and sync deposit history. Returns count of new records."""
        client = await self.get_client(database_id)
        history = await client.client.get_deposit_history()

        async with self.db.session() as session:
            account = await session.get(BybitAccount, database_id)
            if not account or not account.uid:
                raise ValueError(f"Account {database_id} has no uid")

            count = 0
            for record in history.get("records", []):
                # Check if already exists
                existing = await session.get(
                    DepositHistory,
                    (record.get("id"), account.uid),
                )
                if existing:
                    continue

                dep = DepositHistory(
                    id=record.get("id"),
                    uid=account.uid,
                    tx_id=record.get("tx_id", ""),
                    coin_symbol=record.get("coin_symbol", ""),
                    chain_type=record.get("chain_type", ""),
                    chain_name=record.get("chain_name", ""),
                    address=record.get("address", ""),
                    amount=record.get("amount", 0.0),
                    fee=record.get("fee", 0.0),
                    status=record.get("status", ""),
                )
                session.add(dep)
                count += 1

            await session.commit()
        return count

    async def sync_withdraw_history(
        self,
        database_id: int,
    ) -> int:
        """Fetch and sync withdraw history. Returns count of new records."""
        client = await self.get_client(database_id)
        history = await client.client.get_withdraw_history()

        async with self.db.session() as session:
            account = await session.get(BybitAccount, database_id)
            if not account or not account.uid:
                raise ValueError(f"Account {database_id} has no uid")

            count = 0
            for record in history.get("records", []):
                existing = await session.get(
                    WithdrawHistory,
                    (record.get("id"), account.uid),
                )
                if existing:
                    continue

                wh = WithdrawHistory(
                    id=record.get("id"),
                    uid=account.uid,
                    tx_id=record.get("tx_id", ""),
                    request_id=record.get("request_id", ""),
                    coin_symbol=record.get("coin_symbol", ""),
                    chain_type=record.get("chain_type", ""),
                    chain_name=record.get("chain_name", ""),
                    address=record.get("address", ""),
                    amount=record.get("amount", 0.0),
                    fee=record.get("fee", 0.0),
                    status=record.get("status", ""),
                )
                session.add(wh)
                count += 1

            await session.commit()
        return count
