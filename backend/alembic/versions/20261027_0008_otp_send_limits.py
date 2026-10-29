"""Persist privacy-preserving OTP send-rate counters."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261027_0008"
down_revision: str | None = "20261027_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "otp_send_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("recipient_hash", sa.String(length=64), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_otp_send_attempts_recipient_hash", "otp_send_attempts", ["recipient_hash"])
    op.create_index("ix_otp_send_attempts_ip_hash", "otp_send_attempts", ["ip_hash"])
    op.create_index("ix_otp_send_attempts_created_at", "otp_send_attempts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_otp_send_attempts_created_at", table_name="otp_send_attempts")
    op.drop_index("ix_otp_send_attempts_ip_hash", table_name="otp_send_attempts")
    op.drop_index("ix_otp_send_attempts_recipient_hash", table_name="otp_send_attempts")
    op.drop_table("otp_send_attempts")
