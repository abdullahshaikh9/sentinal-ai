from datetime import datetime
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Literal

from app.services.scanning.policy import TargetValidationError, normalize_target_url


class HealthResponse(BaseModel):
    status: str
    service: str


class UserCreate(BaseModel):
    email: str
    display_name: str
    phone_number: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) or len(value) > 320:
            raise ValueError("A valid email address is required.")
        return value

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 120:
            raise ValueError("Display name must be between 1 and 120 characters.")
        return value

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, value: str) -> str:
        value = re.sub(r"[\s()-]", "", value.strip())
        if not re.fullmatch(r"\+[1-9]\d{7,14}", value):
            raise ValueError("Phone number must use international format, for example +15551234567.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 12 or not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value) or not re.search(r"\d", value):
            raise ValueError("Password must be at least 12 characters and include upper, lower, and numeric characters.")
        return value


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_login_email(cls, value: str) -> str:
        return value.strip().lower()


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        if not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value) or not re.search(r"\d", value):
            raise ValueError("New password must include upper, lower, and numeric characters.")
        return value


class PasswordResetRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalize_reset_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) or len(value) > 320:
            raise ValueError("A valid email address is required.")
        return value


class PasswordResetVerifyRequest(BaseModel):
    reset_token: str = Field(min_length=20, max_length=256)
    code: str

    @field_validator("code")
    @classmethod
    def validate_reset_code(cls, value: str) -> str:
        if not re.fullmatch(r"\d{6}", value):
            raise ValueError("Verification code must be six digits.")
        return value


class PasswordResetConfirmRequest(BaseModel):
    password_reset_token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_reset_password(cls, value: str) -> str:
        if not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value) or not re.search(r"\d", value):
            raise ValueError("New password must include upper, lower, and numeric characters.")
        return value


class PasswordResetPendingResponse(BaseModel):
    message: str
    reset_token: str
    resend_after_seconds: int = 60


class PasswordResetVerifyResponse(BaseModel):
    message: str
    password_reset_token: str


class PasswordResetCompleteResponse(BaseModel):
    message: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    display_name: str
    created_at: datetime
    email_verified: bool = False
    phone_verified: bool = False
    phone_masked: str | None = None
    is_admin: bool = False


class AuthResponse(BaseModel):
    user: UserRead


class LoginVerificationPendingResponse(BaseModel):
    verification_required: bool = True
    verification_token: str
    channels: list[str]
    email_masked: str
    phone_masked: str
    resend_after_seconds: int


class RegistrationPendingResponse(BaseModel):
    message: str
    verification_token: str
    email: str
    phone_number: str
    email_verification_required: bool = True
    phone_verification_required: bool = True
    resend_after_seconds: int = 60


class OtpVerificationRequest(BaseModel):
    verification_token: str
    channel: str
    code: str

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, value: str) -> str:
        if value not in {"email", "phone"}:
            raise ValueError("Verification channel must be email or phone.")
        return value

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not re.fullmatch(r"\d{6}", value):
            raise ValueError("Verification code must be six digits.")
        return value


class OtpResendRequest(BaseModel):
    verification_token: str
    channel: str

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, value: str) -> str:
        if value not in {"email", "phone"}:
            raise ValueError("Verification channel must be email or phone.")
        return value


class OtpVerificationResponse(BaseModel):
    message: str
    channel: str
    verified: bool
    account_verified: bool
    user: UserRead | None = None


class AssistantTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 4000:
            raise ValueError("Conversation messages must be between 1 and 4000 characters.")
        return value


class AssistantQuery(BaseModel):
    question: str
    scan_id: int | None = None
    finding_id: int | None = None
    history: list[AssistantTurn] = Field(default_factory=list, max_length=12)

    @field_validator("question")
    @classmethod
    def validate_question(cls, value: str) -> str:
        value = value.strip()
        if not 3 <= len(value) <= 4000:
            raise ValueError("Question must be between 3 and 4000 characters.")
        return value


class AssistantStatus(BaseModel):
    configured: bool
    provider: str
    message: str
    local_guidance_available: bool = True


class AssistantResponse(BaseModel):
    answer: str
    provider: str
    provider_message: str | None = None
    scan_id: int | None
    finding_id: int | None
    evidence_references: list[str]


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_url: str
    normalized_url: str | None
    status: str
    risk_score: int | None
    risk_level: str | None
    error_message: str | None
    redirects: list[str] = []
    checks: dict[str, str] = {}
    check_details: dict[str, object] = {}
    asset_id: int | None = None
    created_at: datetime
    completed_at: datetime | None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    stable_id: str | None
    title: str
    severity: str
    category: str | None
    evidence: str | None
    explanation: str | None
    remediation: str | None
    confidence: str | None
    evidence_data: dict[str, object] | None = None
    dedup_key: str | None = None


class FindingDetailRead(FindingRead):
    scan_id: int
    target_url: str
    remediation_status: str = "open"


class FindingOverviewItem(FindingDetailRead):
    pass


class ScanCreate(BaseModel):
    target_url: str
    authorization_confirmed: bool = False
    asset_id: int | None = None

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        try:
            return normalize_target_url(value)
        except TargetValidationError as exc:
            raise ValueError(str(exc)) from exc


class ScanDetail(ScanRead):
    findings: list[FindingRead] = []
    redirects: list[str] = []


class ScanList(BaseModel):
    items: list[ScanRead]
    total: int = 0
    limit: int = 50
    offset: int = 0


class SearchResultRead(BaseModel):
    kind: Literal["asset", "scan", "finding"]
    id: int
    label: str
    description: str
    href: str


class SearchResponse(BaseModel):
    results: list[SearchResultRead]


class AssetCreate(BaseModel):
    target_url: str
    authorization_confirmed: bool = False

    @field_validator("target_url")
    @classmethod
    def validate_asset_url(cls, value: str) -> str:
        try:
            return normalize_target_url(value)
        except TargetValidationError as exc:
            raise ValueError(str(exc)) from exc


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_url: str
    normalized_url: str
    authorization_confirmed: bool
    created_at: datetime


class AssetSecurityRead(AssetRead):
    latest_scan_id: int | None
    latest_scan_status: str | None
    last_scan_at: datetime | None
    latest_risk_score: int | None
    latest_risk_level: str | None
    latest_checks: dict[str, str]
    scan_count: int
    latest_findings: int
    latest_open_findings: int


class AssetOverviewRead(BaseModel):
    items: list[AssetSecurityRead]
    total: int
    limit: int
    offset: int


class VerificationAttemptRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    finding_id: int | None
    status: str
    summary: str | None
    evidence: str | None
    created_at: datetime


class VerificationOverviewItem(BaseModel):
    finding_id: int
    scan_id: int
    target_url: str
    title: str
    stable_id: str | None
    attempts: list[VerificationAttemptRead] = []


class ActivityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    summary: str
    scan_id: int | None
    finding_id: int | None
    created_at: datetime


class DashboardAssetRead(AssetRead):
    latest_scan_id: int | None
    latest_scan_status: str | None
    last_scan_at: datetime | None
    open_findings: int


class DashboardScanRead(ScanRead):
    findings_count: int


class DashboardRiskPoint(BaseModel):
    scan_id: int
    recorded_at: datetime
    risk_score: int


class DashboardOverviewRead(BaseModel):
    assets_total: int
    assets_scanned: int
    scans_total: int
    scans_by_status: dict[str, int]
    findings_by_severity: dict[str, int]
    open_findings: int
    resolved_findings: int
    high_critical_open: int
    awaiting_verification: int
    verification_outcomes: dict[str, int]
    recent_scans: list[DashboardScanRead]
    assets: list[DashboardAssetRead]
    risk_history: list[DashboardRiskPoint]
    activity: list[ActivityEventRead]


class AdminActivityRead(BaseModel):
    id: int
    event_type: str
    summary: str
    actor_user_id: int | None
    actor_email: str | None
    owner_user_id: int | None
    owner_email: str | None
    scan_id: int | None
    finding_id: int | None
    created_at: datetime


class AdminUserRead(BaseModel):
    id: int
    email: str
    display_name: str
    is_active: bool
    is_admin: bool
    email_verified: bool
    phone_verified: bool
    created_at: datetime


class AdminUsersRead(BaseModel):
    items: list[AdminUserRead]
    total: int
    limit: int
    offset: int


class AdminAssetRead(BaseModel):
    id: int
    target_url: str
    normalized_url: str
    owner_id: int | None
    owner_email: str | None
    authorization_confirmed: bool
    created_at: datetime
    scan_count: int
    latest_scan_id: int | None
    latest_scan_status: str | None
    latest_scan_at: datetime | None
    latest_scan_error: str | None


class AdminAssetsRead(BaseModel):
    items: list[AdminAssetRead]
    total: int
    limit: int
    offset: int


class AdminFindingRead(FindingRead):
    scan_id: int
    target_url: str
    owner_id: int | None
    owner_email: str | None
    remediation_status: str
    verification_count: int
    latest_verification_status: str | None


class AdminFindingsRead(BaseModel):
    items: list[AdminFindingRead]
    total: int
    limit: int
    offset: int


class AdminOverviewRead(BaseModel):
    users_total: int
    users_active: int
    assets_total: int
    assets_with_scans: int
    scans_total: int
    scans_by_status: dict[str, int]
    findings_by_severity: dict[str, int]
    verification_outcomes: dict[str, int]
    reports_last_7_days: int
    auth_events_last_24_hours: int
    failed_login_counters_active: int | None
    recent_scans: list[DashboardScanRead]
    risk_history: list[DashboardRiskPoint]
    recent_activity: list[AdminActivityRead]


class AdminHealthRead(BaseModel):
    backend: str
    database: str
    ai_provider: str
    ai_configured: bool
    email_provider: str
    email_configured: bool
    sms_provider: str
    sms_configured: bool
    provider_health_note: str


class AdminDatabaseDiagnosticsRead(BaseModel):
    database: str
    required_tables: dict[str, bool]
    current_revision: str | None
    expected_head: str
    revision_state: str
    error_category: str | None = None
    database_identity: dict[str, object] = Field(default_factory=dict)
    tls: dict[str, bool] = Field(default_factory=dict)
    current_revisions: list[str] = Field(default_factory=list)
    row_counts: dict[str, int] = Field(default_factory=dict)
    schema_compatible: bool | None = None
    schema_issues: list[str] = Field(default_factory=list)


class AdminDiagnosticChallengeRead(BaseModel):
    challenge: str
    expires_in_seconds: int


class AdminDiagnosticExecuteRequest(BaseModel):
    challenge: str = Field(min_length=32, max_length=256)


class AdminUserStatusUpdate(BaseModel):
    is_active: bool
    current_password: str = Field(min_length=1, max_length=128)


class AdminSessionRevokeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    title: str
    message: str
    scan_id: int | None
    finding_id: int | None
    read_at: datetime | None
    created_at: datetime


class ReportHistoryRead(BaseModel):
    id: int
    scan_id: int
    target_url: str
    report_type: str
    created_at: datetime


class RemediationUpdate(BaseModel):
    status: Literal["open", "in_progress", "fixed", "accepted_risk"]


class RemediationRead(BaseModel):
    finding_id: int
    scan_id: int
    target_url: str
    title: str
    severity: str
    remediation: str | None
    status: str
    updated_at: datetime | None


class RemediationChangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    from_status: str | None
    to_status: str
    changed_by: int
    created_at: datetime


class ComparedFinding(BaseModel):
    stable_id: str
    title: str
    severity: str


class SeverityChange(BaseModel):
    stable_id: str
    title: str
    before: str
    after: str


class ScanComparisonRead(BaseModel):
    earlier_scan_id: int
    later_scan_id: int
    target_url: str
    risk_score_before: int | None
    risk_score_after: int | None
    risk_score_delta: int | None
    new_findings: list[ComparedFinding]
    no_longer_observed: list[ComparedFinding]
    still_present: list[ComparedFinding]
    severity_changes: list[SeverityChange]
    limitation: str

