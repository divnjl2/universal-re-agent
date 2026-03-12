"""
CRUD operations — database queries for all tables.

Provides async functions for creating, reading, updating, deleting
records across all ORM models.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import delete as sa_delete, func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from bybit_manager.database.models import (
    BybitAccount, Email, FinanceAccount,
    DepositAddress, DepositHistory,
    WithdrawAddress, WithdrawHistory,
    Award, AirdropHunt, TokenSplash, PuzzleHunt, IDO,
    Web3Wallet, Web3Chain, Web3Token,
)

logger = logging.getLogger("bybit_manager.database.crud")


# ================================================================
# Account CRUD
# ================================================================

async def get_accounts(
    session: AsyncSession,
    group_name: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> Tuple[List[BybitAccount], int]:
    """Get paginated accounts with optional group filter."""
    query = select(BybitAccount)
    if group_name:
        query = query.where(BybitAccount.group_name == group_name)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return list(result.scalars().all()), total


async def get_account(
    session: AsyncSession,
    database_id: int,
) -> Optional[BybitAccount]:
    """Get account by database_id."""
    return await session.get(BybitAccount, database_id)


async def get_account_by_uid(
    session: AsyncSession,
    uid: int,
) -> Optional[BybitAccount]:
    """Get account by Bybit uid."""
    result = await session.execute(
        select(BybitAccount).where(BybitAccount.uid == uid)
    )
    return result.scalar_one_or_none()


async def get_account_by_email(
    session: AsyncSession,
    email_address: str,
) -> Optional[BybitAccount]:
    """Get account by email address."""
    result = await session.execute(
        select(BybitAccount).where(BybitAccount.email_address == email_address)
    )
    return result.scalar_one_or_none()


async def create_account(
    session: AsyncSession,
    email_address: str,
    password: Optional[str] = None,
    group_name: str = "no_group",
    **kwargs,
) -> BybitAccount:
    """Create account (ensures email record exists)."""
    # Ensure email record
    email_obj = await session.get(Email, email_address)
    if not email_obj:
        email_obj = Email(address=email_address)
        session.add(email_obj)

    account = BybitAccount(
        email_address=email_address,
        password=password,
        group_name=group_name,
        **kwargs,
    )
    session.add(account)
    await session.flush()
    return account


async def update_account(
    session: AsyncSession,
    database_id: int,
    **fields,
) -> Optional[BybitAccount]:
    """Update account fields."""
    account = await session.get(BybitAccount, database_id)
    if not account:
        return None
    for key, value in fields.items():
        if value is not None and hasattr(account, key):
            setattr(account, key, value)
    await session.flush()
    return account


async def delete_accounts(
    session: AsyncSession,
    database_ids: List[int],
) -> int:
    """Delete accounts by IDs."""
    result = await session.execute(
        sa_delete(BybitAccount).where(
            BybitAccount.database_id.in_(database_ids)
        )
    )
    return result.rowcount


async def get_groups(session: AsyncSession) -> List[Dict[str, Any]]:
    """Get all groups with account counts."""
    result = await session.execute(
        select(
            BybitAccount.group_name,
            func.count(BybitAccount.database_id),
        ).group_by(BybitAccount.group_name)
    )
    return [
        {"group_name": row[0], "count": row[1]}
        for row in result.all()
    ]


# ================================================================
# Finance accounts
# ================================================================

async def get_finance_accounts(
    session: AsyncSession,
    uid: int,
) -> List[FinanceAccount]:
    """Get all finance account records for a uid."""
    result = await session.execute(
        select(FinanceAccount).where(FinanceAccount.uid == uid)
    )
    return list(result.scalars().all())


async def upsert_finance_account(
    session: AsyncSession,
    uid: int,
    account_type: str,
    balance: float,
) -> FinanceAccount:
    """Insert or update a finance account balance."""
    from bybit_manager.database.models.finance_account import FinanceAccountType
    fa_type = FinanceAccountType(account_type)

    fa = await session.get(FinanceAccount, (uid, fa_type))
    if fa:
        fa.balance = balance
    else:
        fa = FinanceAccount(uid=uid, type=fa_type, balance=balance)
        session.add(fa)
    await session.flush()
    return fa


# ================================================================
# Deposit/Withdraw history
# ================================================================

async def get_deposit_history(
    session: AsyncSession,
    uid: int,
    page: int = 1,
    page_size: int = 100,
) -> Tuple[List[DepositHistory], int]:
    """Get deposit history for a uid."""
    query = select(DepositHistory).where(DepositHistory.uid == uid)
    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.order_by(DepositHistory.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return list(result.scalars().all()), total


async def get_withdraw_history(
    session: AsyncSession,
    uid: int,
    page: int = 1,
    page_size: int = 100,
) -> Tuple[List[WithdrawHistory], int]:
    """Get withdraw history for a uid."""
    query = select(WithdrawHistory).where(WithdrawHistory.uid == uid)
    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.order_by(WithdrawHistory.submitted_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return list(result.scalars().all()), total


# ================================================================
# Awards
# ================================================================

async def get_awards(
    session: AsyncSession,
    uid: int,
    status: Optional[str] = None,
) -> List[Award]:
    """Get awards for a uid."""
    query = select(Award).where(Award.uid == uid)
    if status:
        from bybit_manager.database.models.award import AwardStatus
        query = query.where(Award.status == AwardStatus(status))
    result = await session.execute(query)
    return list(result.scalars().all())


# ================================================================
# Campaign participation
# ================================================================

async def get_airdrophunts(
    session: AsyncSession,
    uid: int,
) -> List[AirdropHunt]:
    """Get airdrop hunt records for a uid."""
    result = await session.execute(
        select(AirdropHunt).where(AirdropHunt.uid == uid)
    )
    return list(result.scalars().all())


async def get_tokensplashes(
    session: AsyncSession,
    uid: int,
) -> List[TokenSplash]:
    """Get token splash records for a uid."""
    result = await session.execute(
        select(TokenSplash).where(TokenSplash.uid == uid)
    )
    return list(result.scalars().all())


async def get_puzzlehunts(
    session: AsyncSession,
    uid: int,
) -> List[PuzzleHunt]:
    """Get puzzle hunt records for a uid."""
    result = await session.execute(
        select(PuzzleHunt).where(PuzzleHunt.uid == uid)
    )
    return list(result.scalars().all())


async def get_idos(
    session: AsyncSession,
    uid: int,
) -> List[IDO]:
    """Get IDO records for a uid."""
    result = await session.execute(
        select(IDO).where(IDO.uid == uid)
    )
    return list(result.scalars().all())


# ================================================================
# Statistics
# ================================================================

async def get_stats(session: AsyncSession) -> Dict[str, Any]:
    """Get database statistics."""
    total = (await session.execute(
        select(func.count(BybitAccount.database_id))
    )).scalar() or 0

    registered = (await session.execute(
        select(func.count(BybitAccount.database_id)).where(
            BybitAccount.registered == True
        )
    )).scalar() or 0

    with_kyc = (await session.execute(
        select(func.count(BybitAccount.database_id)).where(
            BybitAccount.kyc_level > 0
        )
    )).scalar() or 0

    total_balance = (await session.execute(
        select(func.sum(BybitAccount.balance_usd))
    )).scalar() or 0.0

    return {
        "total_accounts": total,
        "registered": registered,
        "with_kyc": with_kyc,
        "total_balance_usd": total_balance,
    }
