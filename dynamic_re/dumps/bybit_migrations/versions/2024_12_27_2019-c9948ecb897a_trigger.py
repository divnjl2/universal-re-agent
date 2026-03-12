"""trigger

Revision ID: c9948ecb897a
Revises: 9f17e744cf77
Create Date: 2024-12-27 20:19:06.201989

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c9948ecb897a"
down_revision: Union[str, None] = "9f17e744cf77"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Создание триггерной функции
    op.execute("""
    CREATE OR REPLACE FUNCTION delete_email_on_account_delete()
    RETURNS TRIGGER AS $$
    BEGIN
        DELETE FROM email WHERE address = OLD.email_address;
        RETURN OLD;
    END;
    $$ LANGUAGE plpgsql;
    """)

    # Создание триггера
    op.execute("""
    CREATE TRIGGER trg_delete_email
    AFTER DELETE ON bybit_account
    FOR EACH ROW
    EXECUTE FUNCTION delete_email_on_account_delete();
    """)


def downgrade():
    # Удаление триггера
    op.execute("""
    DROP TRIGGER IF EXISTS trg_delete_email ON bybit_account;
    """)

    # Удаление триггерной функции
    op.execute("""
    DROP FUNCTION IF EXISTS delete_email_on_account_delete();
    """)
