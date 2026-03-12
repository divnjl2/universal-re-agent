"""add new enum awards values

Revision ID: 8da7886b84c9
Revises: 13c15ad4d433
Create Date: 2026-01-25 11:23:56.175924

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8da7886b84c9'
down_revision: Union[str, None] = '13c15ad4d433'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TYPE subproductline
        ADD VALUE IF NOT EXISTS 'SUB_PRODUCT_LINE_EARN_DAUL_ASSET';
    """)


def downgrade() -> None:
    pass
