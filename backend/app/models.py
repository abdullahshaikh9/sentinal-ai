from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    redirects: Mapped[str | None] = mapped_column(Text, nullable=True)
    check_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    owner_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "dedup_key", name="uq_findings_scan_dedup_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    stable_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(255), nullable=True)


class VerificationAttempt(Base):
    __tablename__ = "verification_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReportMetadata(Base):
    __tablename__ = "report_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("owner_id", "normalized_url", name="uq_assets_owner_normalized_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(nullable=False, default=False)
    owner_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ActivityEvent(Base):
    __tablename__ = "activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    owner_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(32), nullable=True, unique=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    registration_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    code_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OtpSendAttempt(Base):
    __tablename__ = "otp_send_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recipient_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class PasswordResetChallenge(Base):
    """A single-use email reset challenge, isolated from account-verification OTPs."""

    __tablename__ = "password_reset_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    request_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    reset_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    code_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LoginAttempt(Base):
    """Short-lived failed and in-flight login events, addressed by privacy-reduced digests."""

    __tablename__ = "login_attempts"
    __table_args__ = (
        UniqueConstraint("attempt_id", "attempt_key", name="uq_login_attempt_id_key"),
        Index("ix_login_attempt_key_created", "attempt_key", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_key: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class LoginRateLimitMutex(Base):
    """Single short-held DB lock row serializes throttle admission across workers."""

    __tablename__ = "login_rate_limit_mutex"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)


class FindingRemediation(Base):
    __tablename__ = "finding_remediation"

    finding_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    updated_by: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class RemediationChange(Base):
    __tablename__ = "remediation_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    owner_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    changed_by: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

