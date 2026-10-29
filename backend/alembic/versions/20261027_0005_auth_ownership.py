"""Add users, database sessions, and explicit resource ownership.

Legacy scans, assets, and activity events intentionally retain NULL owner_id.
They are preserved but are not visible through authenticated user endpoints.
An administrator must explicitly assign historical records if that is required.
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261027_0005"
down_revision: str | None = "20261027_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("owner_id", sa.Integer(), nullable=True))
    op.add_column("assets", sa.Column("owner_id", sa.Integer(), nullable=True))
    op.add_column("activity_events", sa.Column("owner_id", sa.Integer(), nullable=True))
    op.create_index("ix_scans_owner_id", "scans", ["owner_id"])
    op.create_index("ix_assets_owner_id", "assets", ["owner_id"])
    op.create_index("ix_activity_events_owner_id", "activity_events", ["owner_id"])

    op.drop_constraint("normalized_url", "assets", type_="unique")
    op.create_unique_constraint("uq_assets_owner_normalized_url", "assets", ["owner_id", "normalized_url"])

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_auth_sessions_expires_at", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_table("users")
    op.drop_constraint("uq_assets_owner_normalized_url", "assets", type_="unique")
    op.create_unique_constraint("normalized_url", "assets", ["normalized_url"])
    op.drop_index("ix_activity_events_owner_id", table_name="activity_events")
    op.drop_index("ix_assets_owner_id", table_name="assets")
    op.drop_index("ix_scans_owner_id", table_name="scans")
    op.drop_column("activity_events", "owner_id")
    op.drop_column("assets", "owner_id")
    op.drop_column("scans", "owner_id")
