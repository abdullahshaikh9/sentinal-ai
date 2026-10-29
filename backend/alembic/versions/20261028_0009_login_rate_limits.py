"""Persist failed-login rate counters across workers and restarts."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261028_0009"
down_revision: str | None = "20261027_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_key", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("attempt_id", "attempt_key", name="uq_login_attempt_id_key"),
        mysql_engine="InnoDB",
    )
    op.create_index("ix_login_attempts_created_at", "login_attempts", ["created_at"])
    op.create_index("ix_login_attempts_key_created", "login_attempts", ["attempt_key", "created_at"])
    op.create_table(
        "login_rate_limit_mutex",
        sa.Column("id", sa.Integer(), primary_key=True),
        mysql_engine="InnoDB",
    )
    op.bulk_insert(
        sa.table("login_rate_limit_mutex", sa.column("id", sa.Integer())),
        [{"id": 1}],
    )


def downgrade() -> None:
    op.drop_table("login_rate_limit_mutex")
    op.drop_index("ix_login_attempts_key_created", table_name="login_attempts")
    op.drop_index("ix_login_attempts_created_at", table_name="login_attempts")
    op.drop_table("login_attempts")
