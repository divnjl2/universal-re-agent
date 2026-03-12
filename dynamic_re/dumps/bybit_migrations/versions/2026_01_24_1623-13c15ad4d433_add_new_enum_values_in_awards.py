"""add new enum values

Revision ID: 13c15ad4d433
Revises: b239907a4191
Create Date: 2026-01-24 16:23:36.665396

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '13c15ad4d433'
down_revision: Union[str, None] = 'b239907a4191'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TYPE awardtype
        ADD VALUE IF NOT EXISTS 'AWARD_TYPE_CREDIT';
    """)

    op.execute("""
        ALTER TYPE productline
        ADD VALUE IF NOT EXISTS 'PRODUCT_LINE_TRADFI';
    """)

    op.execute("""
        ALTER TYPE subproductline
        ADD VALUE IF NOT EXISTS 'SUB_PRODUCT_LINE_TRADFI_DEFAULT';
    """)


def downgrade() -> None:
    pass
