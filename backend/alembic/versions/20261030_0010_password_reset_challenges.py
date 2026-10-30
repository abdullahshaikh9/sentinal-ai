"""Persist password reset challenges isolated from account verification OTPs."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261030_0010"
down_revision: str | None = "20261028_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "password_reset_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("request_token_hash", sa.String(length=64), nullable=False),
        sa.Column("reset_token_hash", sa.String(length=64), nullable=True),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("code_salt", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("request_token_hash", name="uq_password_reset_challenges_request_token_hash"),
        sa.UniqueConstraint("reset_token_hash", name="uq_password_reset_challenges_reset_token_hash"),
        mysql_engine="InnoDB",
    )
    op.create_index("ix_password_reset_challenges_user_id", "password_reset_challenges", ["user_id"])
    op.create_index("ix_password_reset_challenges_expires_at", "password_reset_challenges", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_password_reset_challenges_expires_at", table_name="password_reset_challenges")
    op.drop_index("ix_password_reset_challenges_user_id", table_name="password_reset_challenges")
    op.drop_table("password_reset_challenges")
