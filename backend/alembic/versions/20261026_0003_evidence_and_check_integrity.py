"""Add structured evidence, check coverage, and finding idempotency.

Revision ID: 20261026_0003
Revises: 20261026_0002
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261026_0003"
down_revision: str | None = "20261026_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("check_summary", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("evidence_data", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("dedup_key", sa.String(length=255), nullable=True))

    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, scan_id, stable_id FROM findings ORDER BY id")).mappings().all()
    seen: set[tuple[int, str]] = set()
    for row in rows:
        base = row["stable_id"] or f"legacy:{row['id']}"
        key = (row["scan_id"], base)
        dedup_key = base
        if key in seen:
            dedup_key = f"{base}:legacy:{row['id']}"
        seen.add(key)
        connection.execute(
            sa.text("UPDATE findings SET dedup_key = :dedup_key WHERE id = :id"),
            {"dedup_key": dedup_key[:255], "id": row["id"]},
        )

    op.create_unique_constraint("uq_findings_scan_dedup_key", "findings", ["scan_id", "dedup_key"])


def downgrade() -> None:
    op.drop_constraint("uq_findings_scan_dedup_key", "findings", type_="unique")
    op.drop_column("findings", "dedup_key")
    op.drop_column("findings", "evidence_data")
    op.drop_column("scans", "check_summary")
