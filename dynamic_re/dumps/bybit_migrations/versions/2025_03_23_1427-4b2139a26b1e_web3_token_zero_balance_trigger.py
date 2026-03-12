"""web3_token_zero_balance_trigger

Revision ID: 4b2139a26b1e
Revises: 3725561d122d
Create Date: 2025-03-23 14:27:31.826917

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4b2139a26b1e"
down_revision: Union[str, None] = "3725561d122d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Создаем триггерную функцию
    op.execute("""
        CREATE OR REPLACE FUNCTION delete_zero_balance_tokens()
        RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.balance = 0 THEN
                DELETE FROM web3_token
                WHERE wallet_id = NEW.wallet_id
                  AND chain_id = NEW.chain_id
                  AND contract_address = NEW.contract_address;
                RETURN NULL;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Создаем триггер
    op.execute("""
        CREATE TRIGGER trigger_delete_zero_balance
        BEFORE INSERT OR UPDATE ON web3_token
        FOR EACH ROW
        EXECUTE FUNCTION delete_zero_balance_tokens();
    """)


def downgrade() -> None:
    # Удаляем триггер
    op.execute("DROP TRIGGER IF EXISTS trigger_delete_zero_balance ON web3_token;")

    # Удаляем триггерную функцию
    op.execute("DROP FUNCTION IF EXISTS delete_zero_balance_tokens();")
