"""spec_code

Revision ID: dee5d4692d6e
Revises: bb6e74d0db9d
Create Date: 2025-05-13 23:26:56.956398

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "dee5d4692d6e"
down_revision: Union[str, None] = "bb6e74d0db9d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint('award_pkey', 'award', type_='primary')
    op.create_primary_key('award_pkey', 'award', ['id', 'uid', 'spec_code'])


def downgrade() -> None:
    op.drop_constraint('award_pkey', 'award', type_='primary')
    op.create_primary_key('award_pkey', 'award', ['id', 'uid'])
