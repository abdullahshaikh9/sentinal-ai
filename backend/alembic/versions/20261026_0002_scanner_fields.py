"""Add evidence-based scanner result fields.

Revision ID: 20261026_0002
Revises: 20261025_0001
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20261026_0002"
down_revision: str | None = "20261025_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("normalized_url", sa.String(length=2048), nullable=True))
    op.add_column("scans", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("risk_level", sa.String(length=32), nullable=True))
    op.add_column("scans", sa.Column("error_message", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("redirects", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("stable_id", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("category", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("explanation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("confidence", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "remediation")
    op.drop_column("findings", "explanation")
    op.drop_column("findings", "category")
    op.drop_column("findings", "stable_id")
    op.drop_column("scans", "completed_at")
    op.drop_column("scans", "error_message")
    op.drop_column("scans", "redirects")
    op.drop_column("scans", "risk_level")
    op.drop_column("scans", "risk_score")
    op.drop_column("scans", "normalized_url")
