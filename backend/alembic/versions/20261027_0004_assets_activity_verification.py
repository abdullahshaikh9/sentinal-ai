"""Add registered assets, verification evidence, and activity events.

Revision ID: 20261027_0004
Revises: 20261026_0003
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261027_0004"
down_revision: str | None = "20261026_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("asset_id", sa.Integer(), nullable=True))
    op.add_column("verification_attempts", sa.Column("finding_id", sa.Integer(), nullable=True))
    op.add_column("verification_attempts", sa.Column("summary", sa.Text(), nullable=True))
    op.add_column("verification_attempts", sa.Column("evidence", sa.Text(), nullable=True))
    op.create_index("ix_scans_asset_id", "scans", ["asset_id"])
    op.create_index("ix_verification_attempts_finding_id", "verification_attempts", ["finding_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("normalized_url", sa.String(length=2048), nullable=False, unique=True),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "activity_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_activity_events_event_type", "activity_events", ["event_type"])
    op.create_index("ix_activity_events_scan_id", "activity_events", ["scan_id"])
    op.create_index("ix_activity_events_finding_id", "activity_events", ["finding_id"])
    op.create_index("ix_activity_events_created_at", "activity_events", ["created_at"])

    connection = op.get_bind()
    existing = connection.execute(
        sa.text("SELECT id, target_url, normalized_url FROM scans WHERE normalized_url IS NOT NULL ORDER BY id")
    ).mappings().all()
    asset_ids: dict[str, int] = {}
    for row in existing:
        normalized = row["normalized_url"]
        if normalized not in asset_ids:
            connection.execute(
                sa.text("INSERT INTO assets (target_url, normalized_url, authorization_confirmed) VALUES (:target_url, :normalized_url, :authorized)"),
                {"target_url": row["target_url"], "normalized_url": normalized, "authorized": False},
            )
            asset_ids[normalized] = connection.execute(sa.text("SELECT id FROM assets WHERE normalized_url = :normalized"), {"normalized": normalized}).scalar_one()
        connection.execute(sa.text("UPDATE scans SET asset_id = :asset_id WHERE id = :scan_id"), {"asset_id": asset_ids[normalized], "scan_id": row["id"]})


def downgrade() -> None:
    op.drop_index("ix_activity_events_created_at", table_name="activity_events")
    op.drop_index("ix_activity_events_finding_id", table_name="activity_events")
    op.drop_index("ix_activity_events_scan_id", table_name="activity_events")
    op.drop_index("ix_activity_events_event_type", table_name="activity_events")
    op.drop_table("activity_events")
    op.drop_table("assets")
    op.drop_index("ix_verification_attempts_finding_id", table_name="verification_attempts")
    op.drop_index("ix_scans_asset_id", table_name="scans")
    op.drop_column("verification_attempts", "evidence")
    op.drop_column("verification_attempts", "summary")
    op.drop_column("verification_attempts", "finding_id")
    op.drop_column("scans", "asset_id")
