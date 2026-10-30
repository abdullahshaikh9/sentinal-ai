import json
import logging
import hashlib
import secrets
import csv
import io
from collections import defaultdict
from datetime import UTC, date as Date, datetime, time, timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import and_, case, func, inspect, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from app.config import get_settings
from app.db import DatabaseUnavailableError, check_database_connection, database_error_category, get_db
from app.models import ActivityEvent, Asset, AuthSession, Finding, FindingRemediation, LoginAttempt, Notification, OtpChallenge, PasswordResetChallenge, RemediationChange, ReportMetadata, Scan, User, VerificationAttempt
from app.schemas import ActivityEventRead, AdminActivityRead, AdminAssetRead, AdminAssetsRead, AdminDatabaseDiagnosticsRead, AdminFindingRead, AdminFindingsRead, AdminHealthRead, AdminOverviewRead, AdminSessionRevokeRequest, AdminUserRead, AdminUsersRead, AdminUserStatusUpdate, AssetCreate, AssetOverviewRead, AssetRead, AssetSecurityRead, AssistantQuery, AssistantResponse, AssistantStatus, AuthResponse, ComparedFinding, DashboardAssetRead, DashboardOverviewRead, DashboardRiskPoint, DashboardScanRead, FindingDetailRead, FindingOverviewItem, FindingRead, HealthResponse, LoginRequest, LoginVerificationPendingResponse, NotificationRead, OtpResendRequest, OtpVerificationRequest, OtpVerificationResponse, PasswordChangeRequest, PasswordResetCompleteResponse, PasswordResetConfirmRequest, PasswordResetPendingResponse, PasswordResetRequest, PasswordResetVerifyRequest, PasswordResetVerifyResponse, RegistrationPendingResponse, RemediationChangeRead, RemediationRead, RemediationUpdate, ReportHistoryRead, ScanComparisonRead, ScanCreate, ScanDetail, ScanList, ScanRead, SearchResponse, SearchResultRead, SeverityChange, UserCreate, UserRead, VerificationAttemptRead, VerificationOverviewItem
from app.services.activity import record_event
from app.services.ai import AIProviderError, AIRateLimitError, MAX_CONTEXT_FINDINGS, assistant_http_error, ask_provider, build_context, check_rate_limit, configuration_message, provider_context_budget, provider_is_configured, provider_name
from app.services.guidance import build_defensive_guidance
from app.services.auth import clear_auth_cookies, clear_login_failures, create_session, finalize_login_attempt, get_current_user, hash_password, normalize_email, require_csrf, reserve_login_attempt, set_auth_cookies, verify_password
from app.services.otp import OtpSendRateLimitError, check_send_cooldown, check_send_rate_limits, configuration_message as otp_configuration_message, create_challenge, create_password_reset_challenge, deliver, deliver_password_reset_otp, email_provider_configured, get_challenge, log_delivery_failure, normalize_phone, providers_configured, record_send_attempts, sms_provider_configured, verify_code, verify_password_reset_code
from app.services.reports import build_scan_pdf
from app.services.scanning.jobs import execute_scan
from app.services.verification import execute_verification

router = APIRouter()
assistant_logger = logging.getLogger("sentinel.assistant")
auth_delivery_logger = logging.getLogger("sentinel.auth.delivery")


def _administrator_ids() -> frozenset[int]:
    return get_settings().administrator_ids


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.id not in _administrator_ids():
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return user


def _user_read(user: User) -> UserRead:
    return UserRead(id=user.id, email=user.email, display_name=user.display_name, created_at=user.created_at, email_verified=user.email_verified_at is not None, phone_verified=user.phone_verified_at is not None, phone_masked=_mask_phone(user.phone_number) if user.phone_number else None, is_admin=user.id in _administrator_ids())


def _deliver_registration_otps(user: User, email_code: str, phone_code: str, settings) -> list[str]:
    failures: list[str] = []
    for channel, code in (("email", email_code), ("phone", phone_code)):
        try:
            deliver(channel, user, code, settings)
        except Exception as exc:
            log_delivery_failure(channel, settings, exc)
            failures.append(channel)
    return failures


def _mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    return f"{local[:1]}***@{domain}" if separator else "***"


def _mask_phone(phone: str | None) -> str:
    if not phone:
        return "Unavailable"
    return f"{'*' * max(0, len(phone) - 4)}{phone[-4:]}"


def _notify(db: Session, user_id: int, event_type: str, title: str, message: str, scan_id: int | None = None, finding_id: int | None = None) -> None:
    db.add(Notification(user_id=user_id, event_type=event_type, title=title, message=message[:500], scan_id=scan_id, finding_id=finding_id))


@router.post("/auth/register", response_model=RegistrationPendingResponse, status_code=status.HTTP_202_ACCEPTED, tags=["auth"])
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> RegistrationPendingResponse:
    settings = get_settings()
    if not providers_configured(settings):
        raise HTTPException(status_code=503, detail=otp_configuration_message(settings))
    email = normalize_email(payload.email)
    phone_number = normalize_phone(payload.phone_number)
    if db.scalar(select(User).where(User.email == email)) is not None or db.scalar(select(User).where(User.phone_number == phone_number)) is not None:
        raise HTTPException(status_code=409, detail="An account with that email or phone number already exists.")
    recipients = [email, phone_number]
    try:
        check_send_rate_limits(db, recipients, request.client.host if request.client else "unknown", settings)
    except OtpSendRateLimitError as exc:
        db.rollback()
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    raw_verification_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_verification_token.encode()).hexdigest()
    user = User(email=email, phone_number=phone_number, display_name=payload.display_name, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.flush()
        _, email_code = create_challenge(db, user, "email", token_hash, settings)
        _, phone_code = create_challenge(db, user, "phone", token_hash, settings)
        record_send_attempts(db, recipients, request.client.host if request.client else "unknown", settings)
        record_event(db, "auth.registration_pending", "A new account was created and awaits contact verification.", owner_id=user.id)
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with that email or phone number already exists.") from exc
    failures = _deliver_registration_otps(user, email_code, phone_code, settings)
    if failures:
        raise HTTPException(status_code=503, detail="One or more verification messages could not be delivered. Check the backend delivery logs and try again.")
    return RegistrationPendingResponse(message="Verification messages were accepted by the configured providers.", verification_token=raw_verification_token, email=user.email, phone_number=user.phone_number or "", resend_after_seconds=settings.otp_resend_cooldown_seconds)


@router.post("/auth/login", response_model=AuthResponse | LoginVerificationPendingResponse, tags=["auth"])
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> AuthResponse | LoginVerificationPendingResponse:
    email = normalize_email(payload.email)
    reservation = reserve_login_attempt(request, email, db)
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(payload.password, user.password_hash):
        finalize_login_attempt(reservation, db, outcome="failed")
        record_event(db, "auth.login_failed", "A sign-in attempt was rejected.", owner_id=user.id if user else None)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        finalize_login_attempt(reservation, db, outcome="release")
        raise HTTPException(status_code=401, detail="This account is unavailable.")
    missing_channels = [channel for channel, verified_at in (("email", user.email_verified_at), ("phone", user.phone_verified_at)) if verified_at is None]
    if missing_channels:
        finalize_login_attempt(reservation, db, outcome="failed")
        record_event(db, "auth.login_verification_required", "A password-authenticated sign-in requires contact verification.", owner_id=user.id)
        db.commit()
        settings = get_settings()
        if not providers_configured(settings):
            auth_delivery_logger.error("Login verification unavailable user_id=%s app_env=%s email_provider=%s sms_provider=%s", user.id, settings.app_env, settings.email_provider, settings.sms_provider)
            raise HTTPException(status_code=503, detail=otp_configuration_message(settings))
        if "phone" in missing_channels and not user.phone_number:
            raise HTTPException(status_code=409, detail="A mobile number is not available for this account. Contact support to update it securely.")

        raw_verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_verification_token.encode()).hexdigest()
        now = datetime.now(UTC)
        latest_by_channel: dict[str, OtpChallenge | None] = {}
        resend_after = 0
        for channel in missing_channels:
            latest = db.scalar(select(OtpChallenge).where(OtpChallenge.user_id == user.id, OtpChallenge.channel == channel).order_by(OtpChallenge.created_at.desc(), OtpChallenge.id.desc()))
            latest_by_channel[channel] = latest
            if latest is not None:
                sent_at = latest.last_sent_at.replace(tzinfo=UTC) if latest.last_sent_at.tzinfo is None else latest.last_sent_at
                expires_at = latest.expires_at.replace(tzinfo=UTC) if latest.expires_at.tzinfo is None else latest.expires_at
                usable = expires_at > now and latest.attempts < settings.otp_max_attempts
                remaining = max(0, settings.otp_resend_cooldown_seconds - int((now - sent_at).total_seconds()))
                if not usable and remaining:
                    resend_after = max(resend_after, remaining)
                auth_delivery_logger.info("Login OTP challenge checked channel=%s user_id=%s usable=%s resend_after_seconds=%s", channel, user.id, usable, remaining)
            else:
                auth_delivery_logger.info("Login OTP challenge missing channel=%s user_id=%s action=create_and_deliver", channel, user.id)
        if resend_after:
            raise HTTPException(status_code=429, detail=f"Please wait {resend_after} seconds before requesting a new verification code.")

        deliveries: list[tuple[str, str]] = []
        for channel in missing_channels:
            latest = latest_by_channel[channel]
            if latest is not None:
                expires_at = latest.expires_at.replace(tzinfo=UTC) if latest.expires_at.tzinfo is None else latest.expires_at
                sent_at = latest.last_sent_at.replace(tzinfo=UTC) if latest.last_sent_at.tzinfo is None else latest.last_sent_at
                remaining = max(0, settings.otp_resend_cooldown_seconds - int((now - sent_at).total_seconds()))
                if expires_at > now and latest.attempts < settings.otp_max_attempts and remaining > 0:
                    # Password-authenticated resume: rebind a still-valid challenge to a fresh,
                    # short-lived client capability without resending or revealing its code.
                    db.add(OtpChallenge(user_id=user.id, channel=channel, registration_token_hash=token_hash, code_hash=latest.code_hash, code_salt=latest.code_salt, attempts=latest.attempts, expires_at=latest.expires_at, last_sent_at=latest.last_sent_at))
                    resend_after = max(resend_after, remaining)
                    auth_delivery_logger.info("Login OTP challenge reused channel=%s user_id=%s reason=resend_cooldown resend_after_seconds=%s", channel, user.id, remaining)
                    continue
                if expires_at > now and latest.attempts < settings.otp_max_attempts:
                    auth_delivery_logger.info("Login OTP challenge refresh channel=%s user_id=%s reason=resend_cooldown_elapsed action=create_and_deliver", channel, user.id)
            _, code = create_challenge(db, user, channel, token_hash, settings)
            deliveries.append((channel, code))
            resend_after = max(resend_after, settings.otp_resend_cooldown_seconds)
        if deliveries:
            recipients = [user.email if channel == "email" else user.phone_number or "" for channel, _ in deliveries]
            try:
                check_send_rate_limits(db, recipients, request.client.host if request.client else "unknown", settings)
            except OtpSendRateLimitError as exc:
                db.rollback()
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            record_send_attempts(db, recipients, request.client.host if request.client else "unknown", settings)
        db.commit()
        failures: list[str] = []
        for channel, code in deliveries:
            try:
                deliver(channel, user, code, settings)
            except Exception as exc:
                log_delivery_failure(channel, settings, exc)
                failures.append(channel)
        if failures:
            raise HTTPException(status_code=503, detail="Verification delivery failed. Check the backend delivery logs and retry after the resend cooldown.")
        return LoginVerificationPendingResponse(verification_token=raw_verification_token, channels=missing_channels, email_masked=_mask_email(user.email), phone_masked=_mask_phone(user.phone_number), resend_after_seconds=resend_after)
    finalize_login_attempt(reservation, db, outcome="success")
    raw_token, raw_csrf, _ = create_session(db, user)
    record_event(db, "auth.login_succeeded", "A user signed in successfully.", owner_id=user.id)
    db.commit()
    set_auth_cookies(response, raw_token, raw_csrf)
    return AuthResponse(user=_user_read(user))


@router.post("/auth/verify-otp", response_model=OtpVerificationResponse, tags=["auth"])
def verify_otp(payload: OtpVerificationRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> OtpVerificationResponse:
    settings = get_settings()
    token_hash = hashlib.sha256(payload.verification_token.encode()).hexdigest()
    challenge = get_challenge(db, token_hash, payload.channel)
    if challenge is None:
        raise HTTPException(status_code=400, detail="The verification request is invalid or expired.")
    user = db.get(User, challenge.user_id)
    now = datetime.now(UTC)
    expires_at = challenge.expires_at.replace(tzinfo=UTC) if challenge.expires_at.tzinfo is None else challenge.expires_at
    if user is None or challenge.verified_at is not None:
        return OtpVerificationResponse(message="This verification channel is already complete.", channel=payload.channel, verified=True, account_verified=user is not None and user.email_verified_at is not None and user.phone_verified_at is not None)
    if expires_at <= now or challenge.attempts >= settings.otp_max_attempts:
        record_event(db, "auth.otp_rejected", f"An expired or exhausted {payload.channel} verification challenge was rejected.", owner_id=user.id if user else None)
        db.commit()
        raise HTTPException(status_code=400, detail="The verification code is expired or has too many failed attempts.")
    if not verify_code(challenge, payload.code, settings):
        db.execute(update(OtpChallenge).where(OtpChallenge.user_id == challenge.user_id, OtpChallenge.channel == challenge.channel, OtpChallenge.code_hash == challenge.code_hash).values(attempts=OtpChallenge.attempts + 1))
        record_event(db, "auth.otp_failed", f"A {payload.channel} verification attempt was rejected.", owner_id=user.id)
        db.commit()
        raise HTTPException(status_code=400, detail="The verification code is incorrect.")
    challenge.verified_at = now
    if payload.channel == "email":
        user.email_verified_at = now
    else:
        user.phone_verified_at = now
    account_verified = user.email_verified_at is not None and user.phone_verified_at is not None
    if account_verified:
        clear_login_failures(request, user.email, db)
        raw_token, raw_csrf, _ = create_session(db, user)
    record_event(db, "auth.otp_verified", f"The {payload.channel} verification channel was verified.", owner_id=user.id)
    db.commit()
    if account_verified:
        set_auth_cookies(response, raw_token, raw_csrf)
    return OtpVerificationResponse(message="Verification complete." if account_verified else "Channel verified. Verify the other channel to activate your account.", channel=payload.channel, verified=True, account_verified=account_verified, user=_user_read(user) if account_verified else None)


@router.post("/auth/resend-otp", status_code=status.HTTP_202_ACCEPTED, tags=["auth"])
def resend_otp(payload: OtpResendRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str | int]:
    settings = get_settings()
    if not providers_configured(settings):
        raise HTTPException(status_code=503, detail=otp_configuration_message(settings))
    token_hash = hashlib.sha256(payload.verification_token.encode()).hexdigest()
    challenge = get_challenge(db, token_hash, payload.channel)
    if challenge is None:
        raise HTTPException(status_code=400, detail="The verification request is invalid or expired.")
    user = db.get(User, challenge.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="The verification request is invalid or expired.")
    if (payload.channel == "email" and user.email_verified_at is not None) or (payload.channel == "phone" and user.phone_verified_at is not None):
        raise HTTPException(status_code=409, detail="This verification channel is already complete.")
    last_sent = challenge.last_sent_at.replace(tzinfo=UTC) if challenge.last_sent_at.tzinfo is None else challenge.last_sent_at
    if datetime.now(UTC) - last_sent < timedelta(seconds=settings.otp_resend_cooldown_seconds):
        raise HTTPException(status_code=429, detail="Please wait before requesting another verification code.")
    recipient = user.email if payload.channel == "email" else user.phone_number or ""
    try:
        check_send_rate_limits(db, [recipient], request.client.host if request.client else "unknown", settings)
    except OtpSendRateLimitError as exc:
        db.rollback()
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    _, code = create_challenge(db, user, payload.channel, token_hash, settings)
    record_send_attempts(db, [recipient], request.client.host if request.client else "unknown", settings)
    db.commit()
    try:
        deliver(payload.channel, user, code, settings)
    except Exception as exc:
        log_delivery_failure(payload.channel, settings, exc)
        raise HTTPException(status_code=503, detail="Verification delivery is temporarily unavailable. Check the backend delivery logs and try again.") from exc
    return {"message": "The verification message was accepted by the configured provider.", "resend_after_seconds": settings.otp_resend_cooldown_seconds}


@router.get("/auth/me", response_model=UserRead, tags=["auth"])
def current_user(user: User = Depends(get_current_user)) -> UserRead:
    return _user_read(user)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
def logout(response: Response, session: AuthSession = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    stored_session = db.merge(session)
    stored_session.revoked_at = datetime.now(UTC)
    db.commit()
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/auth/change-password", tags=["auth"])
def change_password(payload: PasswordChangeRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user), session: AuthSession = Depends(require_csrf)) -> dict[str, str]:
    reservation = reserve_login_attempt(request, user.email, db)
    if not verify_password(payload.current_password, user.password_hash):
        finalize_login_attempt(reservation, db, outcome="failed")
        record_event(db, "auth.password_change_failed", "A password change was rejected.", owner_id=user.id)
        db.commit()
        raise HTTPException(status_code=400, detail="The current password is incorrect.")
    if verify_password(payload.new_password, user.password_hash):
        finalize_login_attempt(reservation, db, outcome="release")
        raise HTTPException(status_code=400, detail="Choose a different password.")
    finalize_login_attempt(reservation, db, outcome="success")
    user.password_hash = hash_password(payload.new_password)
    now = datetime.now(UTC)
    db.execute(update(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != session.id, AuthSession.revoked_at.is_(None)).values(revoked_at=now))
    record_event(db, "auth.password_changed", "The account password was changed; other active sessions were revoked.", owner_id=user.id)
    _notify(db, user.id, "auth.password_changed", "Account password changed", "Your password was changed. Other active sessions were signed out.")
    db.commit()
    return {"message": "Password changed. Other active sessions were signed out."}


@router.post("/auth/forgot-password", response_model=PasswordResetPendingResponse, tags=["auth"])
@router.post("/auth/request-reset", response_model=PasswordResetPendingResponse, tags=["auth"], include_in_schema=False)
def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PasswordResetPendingResponse:
    settings = get_settings()
    if not email_provider_configured(settings):
        auth_delivery_logger.error("Password reset email delivery unavailable email_provider=%s", settings.email_provider)
        raise HTTPException(status_code=503, detail="Email verification is unavailable until the SMTP provider is configured.")

    email = normalize_email(payload.email)
    client_ip = request.client.host if request.client else "unknown"

    try:
        check_send_cooldown(db, email, settings)
        check_send_rate_limits(db, [email], client_ip, settings)
    except OtpSendRateLimitError as exc:
        db.rollback()
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    record_send_attempts(db, [email], client_ip, settings)

    raw_request_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_request_token.encode()).hexdigest()

    user = db.scalar(select(User).where(User.email == email))
    if user is not None and user.is_active:
        challenge, code = create_password_reset_challenge(db, user, token_hash, settings)
        record_event(db, "auth.password_reset_requested", "A password reset code was requested.", owner_id=user.id)
        db.commit()
        try:
            deliver_password_reset_otp(user, code, settings)
        except Exception as exc:
            log_delivery_failure("email", settings, exc)
            raise HTTPException(status_code=503, detail="Password reset delivery failed. Check the backend delivery logs and retry.") from exc
    else:
        db.commit()

    return PasswordResetPendingResponse(
        message="If an account exists with that email, a password reset code has been sent.",
        reset_token=raw_request_token,
        resend_after_seconds=settings.otp_resend_cooldown_seconds,
    )


@router.post("/auth/verify-reset-code", response_model=PasswordResetVerifyResponse, tags=["auth"])
@router.post("/auth/verify-reset-otp", response_model=PasswordResetVerifyResponse, tags=["auth"], include_in_schema=False)
def verify_reset_otp(
    payload: PasswordResetVerifyRequest,
    db: Session = Depends(get_db),
) -> PasswordResetVerifyResponse:
    settings = get_settings()
    token_hash = hashlib.sha256(payload.reset_token.encode()).hexdigest()
    challenge = db.scalar(
        select(PasswordResetChallenge)
        .where(PasswordResetChallenge.request_token_hash == token_hash)
        .with_for_update()
    )
    if challenge is None:
        raise HTTPException(status_code=400, detail="The reset request is invalid or expired.")

    now = datetime.now(UTC)
    expires_at = challenge.expires_at.replace(tzinfo=UTC) if challenge.expires_at.tzinfo is None else challenge.expires_at

    if challenge.used_at is not None or challenge.verified_at is not None:
        raise HTTPException(status_code=400, detail="This reset request has already been used.")

    if expires_at <= now or challenge.attempts >= settings.otp_max_attempts:
        record_event(db, "auth.password_reset_rejected", "An expired or exhausted password reset challenge was rejected.", owner_id=challenge.user_id)
        db.commit()
        raise HTTPException(status_code=400, detail="The reset code is expired or has too many failed attempts.")

    if not verify_password_reset_code(challenge, payload.code, settings):
        challenge.attempts += 1
        record_event(db, "auth.password_reset_failed", "A password reset verification code was rejected.", owner_id=challenge.user_id)
        db.commit()
        raise HTTPException(status_code=400, detail="The verification code is incorrect.")

    challenge.verified_at = now
    raw_password_reset_token = secrets.token_urlsafe(32)
    challenge.reset_token_hash = hashlib.sha256(raw_password_reset_token.encode()).hexdigest()
    record_event(db, "auth.password_reset_verified", "A password reset verification code was verified.", owner_id=challenge.user_id)
    db.commit()

    return PasswordResetVerifyResponse(
        message="Verification code accepted. Please set a new password.",
        password_reset_token=raw_password_reset_token,
    )


@router.post("/auth/reset-password", response_model=PasswordResetCompleteResponse, tags=["auth"])
def confirm_password_reset(
    payload: PasswordResetConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PasswordResetCompleteResponse:
    token_hash = hashlib.sha256(payload.password_reset_token.encode()).hexdigest()
    challenge = db.scalar(
        select(PasswordResetChallenge)
        .where(PasswordResetChallenge.reset_token_hash == token_hash)
        .with_for_update()
    )
    if challenge is None or challenge.verified_at is None:
        raise HTTPException(status_code=400, detail="The reset token is invalid or expired.")

    if challenge.used_at is not None:
        raise HTTPException(status_code=400, detail="This reset token has already been used.")

    now = datetime.now(UTC)
    expires_at = challenge.expires_at.replace(tzinfo=UTC) if challenge.expires_at.tzinfo is None else challenge.expires_at
    if expires_at <= now:
        raise HTTPException(status_code=400, detail="The reset token has expired.")

    user = db.get(User, challenge.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="This account is unavailable.")

    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Choose a different password.")

    user.password_hash = hash_password(payload.new_password)
    challenge.used_at = now

    db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )

    clear_login_failures(request, user.email, db)

    record_event(db, "auth.password_reset_completed", "The account password was reset; all active sessions were revoked.", owner_id=user.id)
    _notify(db, user.id, "auth.password_reset_completed", "Password reset successful", "Your password was reset successfully. All previous active sessions were signed out.")
    db.commit()

    return PasswordResetCompleteResponse(
        message="Your password has been reset successfully. Please sign in with your new password."
    )


@router.get("/assistant/status", response_model=AssistantStatus, tags=["assistant"])
def assistant_status(user: User = Depends(get_current_user)) -> AssistantStatus:
    del user
    settings = get_settings()
    configured = provider_is_configured(settings)
    message = configuration_message(settings)
    if not configured:
        message += " Select a saved scan to get local defensive guidance from its persisted findings."
    return AssistantStatus(configured=configured, provider=provider_name(settings), message=message, local_guidance_available=True)


@router.post("/assistant/query", response_model=AssistantResponse, tags=["assistant"])
def assistant_query(payload: AssistantQuery, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> AssistantResponse:
    del _csrf
    settings = get_settings()
    provider_message = None
    try:
        check_rate_limit(user.id, settings)
        scan = db.scalar(select(Scan).where(Scan.id == payload.scan_id, Scan.owner_id == user.id)) if payload.scan_id is not None else None
        if payload.scan_id is not None and scan is None:
            raise HTTPException(status_code=404, detail="The selected scan was not found.")
        finding = None
        finding_model = None
        scan_findings = []
        omitted_findings = 0
        if payload.finding_id is not None:
            finding_model = db.scalar(select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Finding.id == payload.finding_id, Scan.owner_id == user.id))
            if finding_model is None or (scan is not None and finding_model.scan_id != scan.id):
                raise HTTPException(status_code=404, detail="The selected finding was not found.")
            if scan is None:
                scan = db.get(Scan, finding_model.scan_id)
            safe_evidence_data = None
            if finding_model.evidence_data:
                try:
                    parsed_evidence = json.loads(finding_model.evidence_data)
                    if isinstance(parsed_evidence, dict):
                        safe_evidence_data = {key: parsed_evidence[key] for key in ("cookie_name", "observed_attributes") if key in parsed_evidence}
                except (TypeError, ValueError):
                    safe_evidence_data = None
            finding = {"id": finding_model.id, "title": finding_model.title, "severity": finding_model.severity, "category": finding_model.category, "evidence": finding_model.evidence, "explanation": finding_model.explanation, "remediation": finding_model.remediation, "confidence": finding_model.confidence, "evidence_data": safe_evidence_data}
        elif scan is not None:
            severity_order = case((Finding.severity == "critical", 0), (Finding.severity == "high", 1), (Finding.severity == "medium", 2), (Finding.severity == "low", 3), else_=4)
            total_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0
            scan_findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(severity_order, Finding.id).limit(MAX_CONTEXT_FINDINGS)).all()
            omitted_findings = max(0, total_findings - len(scan_findings))
        checks = scan.check_summary if scan is not None else None
        # A target URL is not needed for recommendations; keep it out of third-party prompts.
        finding_contexts = [{"id": item.id, "title": item.title, "severity": item.severity, "category": item.category, "evidence": item.evidence, "explanation": item.explanation, "remediation": item.remediation, "confidence": item.confidence} for item in scan_findings]
        history = [{"role": turn.role, "content": turn.content} for turn in payload.history]
        context, references = build_context(
            target_url=None, scan_id=scan.id if scan else None, finding_id=payload.finding_id,
            scan_status=scan.status if scan else None, risk_score=scan.risk_score if scan else None,
            risk_level=scan.risk_level if scan else None, checks=checks, finding=finding,
            findings=finding_contexts,
            max_chars=provider_context_budget(payload.question, history, settings),
            omitted_findings=omitted_findings,
        )
        if provider_is_configured(settings):
            try:
                answer = ask_provider(payload.question, context, settings, history)
                provider = provider_name(settings)
            except (AIProviderError, AIRateLimitError) as exc:
                if scan is None:
                    raise
                guidance_findings = [finding_model] if finding_model is not None else scan_findings
                answer = build_defensive_guidance(scan, guidance_findings, omitted_findings=omitted_findings, max_chars=settings.ai_max_output_chars)
                provider = "local-evidence-fallback"
                provider_message = str(exc)
                assistant_logger.warning("Assistant used local scan fallback reason=%s status_code=%s", getattr(exc, "reason_code", "rate_limited"), getattr(exc, "status_code", None))
        elif scan is not None:
            guidance_findings = [finding_model] if finding_model is not None else scan_findings
            answer = build_defensive_guidance(scan, guidance_findings, omitted_findings=omitted_findings, max_chars=settings.ai_max_output_chars)
            provider = "local-evidence-fallback"
            provider_message = configuration_message(settings)
            assistant_logger.warning("Assistant used local scan fallback reason=provider_unconfigured provider=%s", provider_name(settings))
        else:
            answer = ask_provider(payload.question, context, settings, history)
            provider = provider_name(settings)
    except HTTPException:
        raise
    except RuntimeError as exc:
        raise assistant_http_error(exc) from exc
    if provider == "local-evidence-fallback":
        if scan is not None:
            fallback_findings = [finding_model] if finding_model is not None else scan_findings
            references = [f"scan:{scan.id}", *(f"finding:{item.id}" for item in fallback_findings)]
        references = [reference for reference in references if reference in answer]
    return AssistantResponse(answer=answer, provider=provider, provider_message=provider_message, scan_id=scan.id if scan else None, finding_id=payload.finding_id, evidence_references=references)


def _scan_read(scan: Scan) -> ScanRead:
    parsed_checks = json.loads(scan.check_summary) if scan.check_summary else {}
    if isinstance(parsed_checks, dict) and isinstance(parsed_checks.get("coverage"), dict):
        checks = {key: value for key, value in parsed_checks["coverage"].items() if isinstance(key, str) and isinstance(value, str)}
        details = parsed_checks.get("details") if isinstance(parsed_checks.get("details"), dict) else {}
    else:
        # Backwards-compatible reader for scans saved before structured details.
        checks = parsed_checks if isinstance(parsed_checks, dict) else {}
        checks = {key: value for key, value in checks.items() if isinstance(key, str) and isinstance(value, str)}
        details = {}
    return ScanRead(
        id=scan.id,
        target_url=scan.target_url,
        normalized_url=scan.normalized_url,
        status=scan.status,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        redirects=json.loads(scan.redirects) if scan.redirects else [],
        checks=checks,
        check_details=details,
        asset_id=scan.asset_id,
    )


def _safe_check_summary(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    coverage = parsed.get("coverage") if isinstance(parsed.get("coverage"), dict) else parsed
    return {key: state for key, state in coverage.items() if isinstance(key, str) and isinstance(state, str)}


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    try:
        check_database_connection()
    except DatabaseUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return HealthResponse(status="ok", service=get_settings().app_name)


@router.get("/search", response_model=SearchResponse, tags=["search"])
def search(q: str = Query(min_length=1, max_length=100), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> SearchResponse:
    """Search only the authenticated user's assets, scans, and scan findings."""
    needle = q.strip()
    if not needle:
        return SearchResponse(results=[])
    escaped = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    pattern = f"%{escaped}%"
    results: list[SearchResultRead] = []
    assets = db.scalars(select(Asset).where(Asset.owner_id == user.id, Asset.normalized_url.ilike(pattern, escape="!")).order_by(Asset.created_at.desc(), Asset.id.desc()).limit(5)).all()
    results.extend(SearchResultRead(kind="asset", id=item.id, label=item.normalized_url, description="Authorized asset", href="/domains") for item in assets)
    scans = db.scalars(select(Scan).where(Scan.owner_id == user.id, Scan.target_url.ilike(pattern, escape="!")).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(5)).all()
    results.extend(SearchResultRead(kind="scan", id=item.id, label=item.target_url, description=f"Scan {item.status}", href=f"/scans/{item.id}") for item in scans)
    findings = db.execute(select(Finding, Scan).join(Scan, Scan.id == Finding.scan_id).where(Scan.owner_id == user.id, Finding.title.ilike(pattern, escape="!")).order_by(Scan.created_at.desc(), Finding.id.desc()).limit(5)).all()
    results.extend(SearchResultRead(kind="finding", id=finding.id, label=finding.title, description=f"{finding.severity.title()} finding · {scan.target_url}", href=f"/findings/{finding.id}") for finding, scan in findings)
    return SearchResponse(results=results)


@router.get("/dashboard/overview", response_model=DashboardOverviewRead, tags=["dashboard"])
def dashboard_overview(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> DashboardOverviewRead:
    """Return bounded dashboard records and account-scoped persisted aggregates."""
    statuses = {key: 0 for key in ("pending", "running", "completed", "partial", "failed")}
    for state, count in db.execute(select(Scan.status, func.count()).where(Scan.owner_id == user.id).group_by(Scan.status)).all():
        if state in statuses:
            statuses[state] = count
    scans_total = sum(statuses.values())
    assets_total = db.scalar(select(func.count()).select_from(Asset).where(Asset.owner_id == user.id)) or 0
    assets_scanned = db.scalar(
        select(func.count(func.distinct(Asset.id))).join(Scan, Scan.asset_id == Asset.id)
        .where(Asset.owner_id == user.id, Scan.owner_id == user.id)
    ) or 0

    severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    open_findings = resolved_findings = high_critical_open = 0
    finding_groups = db.execute(
        select(Finding.severity, FindingRemediation.status, func.count())
        .join(Scan, Scan.id == Finding.scan_id)
        .outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
        .where(Scan.owner_id == user.id)
        .group_by(Finding.severity, FindingRemediation.status)
    ).all()
    for severity, raw_state, count in finding_groups:
        state = raw_state or "open"
        if severity in severity_counts:
            severity_counts[severity] += count
        if state in {"open", "in_progress"}:
            open_findings += count
            if severity in {"critical", "high"}:
                high_critical_open += count
        elif state == "fixed":
            resolved_findings += count

    latest_verification = select(VerificationAttempt.status).where(VerificationAttempt.finding_id == Finding.id).order_by(VerificationAttempt.created_at.desc(), VerificationAttempt.id.desc()).limit(1).scalar_subquery()
    awaiting_verification = db.scalar(
        select(func.count()).select_from(Finding).join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.owner_id == user.id, latest_verification.in_(("pending", "running")))
    ) or 0
    verification_outcomes = {"pending": 0, "running": 0, "inconclusive": 0, "failed": 0}
    for outcome, count in db.execute(
        select(VerificationAttempt.status, func.count()).join(Scan, Scan.id == VerificationAttempt.scan_id)
        .where(Scan.owner_id == user.id).group_by(VerificationAttempt.status)
    ).all():
        verification_outcomes[outcome] = count

    recent_scan_models = db.scalars(select(Scan).where(Scan.owner_id == user.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(6)).all()
    recent_scan_ids = [scan.id for scan in recent_scan_models]
    per_scan_counts = dict(db.execute(select(Finding.scan_id, func.count()).where(Finding.scan_id.in_(recent_scan_ids)).group_by(Finding.scan_id)).all()) if recent_scan_ids else {}
    recent_scans = [DashboardScanRead(**_scan_read(scan).model_dump(), findings_count=per_scan_counts.get(scan.id, 0)) for scan in recent_scan_models]

    latest_scan_id = (
        select(Scan.id)
        .where(Scan.owner_id == user.id, Scan.asset_id == Asset.id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
        .correlate(Asset)
        .scalar_subquery()
    )
    LatestScan = aliased(Scan)
    asset_scan_rows = db.execute(
        select(Asset, LatestScan)
        .outerjoin(LatestScan, and_(LatestScan.id == latest_scan_id, LatestScan.owner_id == user.id))
        .where(Asset.owner_id == user.id)
        .order_by(Asset.created_at.desc(), Asset.id.desc())
        .limit(6)
    ).all()
    latest_scan_ids = [latest.id for _, latest in asset_scan_rows if latest is not None]
    open_counts = dict(
        db.execute(
            select(Finding.scan_id, func.count())
            .outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
            .where(
                Finding.scan_id.in_(latest_scan_ids),
                func.coalesce(FindingRemediation.status, "open").in_(("open", "in_progress")),
            )
            .group_by(Finding.scan_id)
        ).all()
    ) if latest_scan_ids else {}
    asset_rows: list[DashboardAssetRead] = []
    for asset, latest in asset_scan_rows:
        asset_rows.append(DashboardAssetRead(
            **AssetRead.model_validate(asset).model_dump(),
            latest_scan_id=latest.id if latest else None,
            latest_scan_status=latest.status if latest else None,
            last_scan_at=(latest.completed_at or latest.created_at) if latest else None,
            open_findings=open_counts.get(latest.id, 0) if latest is not None else 0,
        ))

    risk_rows = db.execute(
        select(Scan.id, Scan.completed_at, Scan.created_at, Scan.risk_score)
        .where(Scan.owner_id == user.id, Scan.status.in_(("completed", "partial")), Scan.risk_score.is_not(None))
        .order_by(Scan.completed_at.desc(), Scan.created_at.desc(), Scan.id.desc()).limit(12)
    ).all()
    risk_history = [DashboardRiskPoint(scan_id=scan_id, recorded_at=completed_at or created_at, risk_score=score) for scan_id, completed_at, created_at, score in reversed(risk_rows)]
    activities = db.scalars(select(ActivityEvent).where(ActivityEvent.owner_id == user.id).order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).limit(6)).all()
    return DashboardOverviewRead(
        assets_total=assets_total, assets_scanned=assets_scanned, scans_total=scans_total, scans_by_status=statuses,
        findings_by_severity=severity_counts, open_findings=open_findings, resolved_findings=resolved_findings,
        high_critical_open=high_critical_open, awaiting_verification=awaiting_verification,
        verification_outcomes=verification_outcomes, recent_scans=recent_scans, assets=asset_rows,
        risk_history=risk_history, activity=[ActivityEventRead.model_validate(item) for item in activities],
    )


def _admin_user_read(user: User, admin_ids: frozenset[int]) -> AdminUserRead:
    return AdminUserRead(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_active=user.is_active,
        is_admin=user.id in admin_ids,
        email_verified=user.email_verified_at is not None,
        phone_verified=user.phone_verified_at is not None,
        created_at=user.created_at,
    )


@router.get("/admin/overview", response_model=AdminOverviewRead, tags=["admin"])
def admin_overview(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> AdminOverviewRead:
    statuses = {key: 0 for key in ("pending", "running", "completed", "partial", "failed")}
    for state, count in db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all():
        statuses[state] = count

    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for severity, count in db.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all():
        severity_counts[severity] = count

    verification_outcomes: dict[str, int] = {}
    for outcome, count in db.execute(
        select(VerificationAttempt.status, func.count()).group_by(VerificationAttempt.status)
    ).all():
        verification_outcomes[outcome] = count

    users_total = db.scalar(select(func.count()).select_from(User)) or 0
    users_active = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) or 0
    assets_total = db.scalar(select(func.count()).select_from(Asset)) or 0
    assets_with_scans = db.scalar(
        select(func.count(func.distinct(Asset.id)))
        .select_from(Asset)
        .join(Scan, and_(Scan.asset_id == Asset.id, Scan.owner_id == Asset.owner_id))
    ) or 0
    reports_last_7_days = db.scalar(
        select(func.count()).select_from(ReportMetadata).where(
            ReportMetadata.created_at >= datetime.now(UTC) - timedelta(days=7)
        )
    ) or 0
    auth_events_last_24_hours = db.scalar(
        select(func.count()).select_from(ActivityEvent).where(
            ActivityEvent.event_type.like("auth.%"),
            ActivityEvent.created_at >= datetime.now(UTC) - timedelta(hours=24),
        )
    ) or 0

    failed_login_counters_active: int | None = None
    if inspect(db.get_bind()).has_table("login_attempts"):
        failed_login_counters_active = db.scalar(
            select(func.count()).select_from(LoginAttempt).where(
                LoginAttempt.state == "failed",
                LoginAttempt.created_at >= datetime.now(UTC) - timedelta(minutes=15),
            )
        ) or 0

    scan_models = db.scalars(select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(10)).all()
    scan_ids = [scan.id for scan in scan_models]
    finding_counts = dict(
        db.execute(
            select(Finding.scan_id, func.count())
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id)
        ).all()
    ) if scan_ids else {}
    recent_scans = [
        DashboardScanRead(**_scan_read(scan).model_dump(), findings_count=finding_counts.get(scan.id, 0))
        for scan in scan_models
    ]
    risk_rows = db.execute(
        select(Scan.id, Scan.completed_at, Scan.created_at, Scan.risk_score)
        .where(Scan.status.in_(("completed", "partial")), Scan.risk_score.is_not(None))
        .order_by(Scan.completed_at.desc(), Scan.created_at.desc(), Scan.id.desc())
        .limit(30)
    ).all()
    risk_history = [
        DashboardRiskPoint(scan_id=scan_id, recorded_at=completed_at or created_at, risk_score=score)
        for scan_id, completed_at, created_at, score in reversed(risk_rows)
    ]
    activity_rows = db.execute(
        select(ActivityEvent, User.email)
        .outerjoin(User, User.id == ActivityEvent.owner_id)
        .order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc())
        .limit(10)
    ).all()
    recent_activity = [
        AdminActivityRead(
            id=event.id,
            event_type=event.event_type,
            summary=event.summary,
            actor_user_id=event.owner_id if event.event_type.startswith("admin.") else None,
            actor_email=email if event.event_type.startswith("admin.") else None,
            owner_user_id=event.owner_id,
            owner_email=email,
            scan_id=event.scan_id,
            finding_id=event.finding_id,
            created_at=event.created_at,
        )
        for event, email in activity_rows
    ]
    return AdminOverviewRead(
        users_total=users_total,
        users_active=users_active,
        assets_total=assets_total,
        assets_with_scans=assets_with_scans,
        scans_total=sum(statuses.values()),
        scans_by_status=statuses,
        findings_by_severity=severity_counts,
        verification_outcomes=verification_outcomes,
        reports_last_7_days=reports_last_7_days,
        auth_events_last_24_hours=auth_events_last_24_hours,
        failed_login_counters_active=failed_login_counters_active,
        recent_scans=recent_scans,
        risk_history=risk_history,
        recent_activity=recent_activity,
    )


@router.get("/admin/health", response_model=AdminHealthRead, tags=["admin"])
def admin_health(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> AdminHealthRead:
    settings = get_settings()
    database_state = "healthy"
    try:
        db.execute(select(1))
    except Exception:
        db.rollback()
        database_state = "unavailable"
    return AdminHealthRead(
        backend="healthy",
        database=database_state,
        ai_provider=provider_name(settings),
        ai_configured=provider_is_configured(settings),
        email_provider=settings.email_provider.lower(),
        email_configured=email_provider_configured(settings),
        sms_provider=settings.sms_provider.lower(),
        sms_configured=sms_provider_configured(settings),
        provider_health_note="Provider status reflects configuration only; no outbound connectivity check was performed.",
    )


@router.get("/admin/database-diagnostics", response_model=AdminDatabaseDiagnosticsRead, tags=["admin"])
def admin_database_diagnostics(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> AdminDatabaseDiagnosticsRead:
    """Read-only database and migration diagnostics for administrators."""
    expected_head = "20261030_0010"
    required_table_names = ("users", "otp_send_attempts", "password_reset_challenges", "activity_events", "alembic_version")
    try:
        table_names = set(inspect(db.connection()).get_table_names())
        required_tables = {name: name in table_names for name in required_table_names}
        current_revision = None
        revision_state = "missing_revision_table" if "alembic_version" not in table_names else "unknown"
        if "alembic_version" in table_names:
            revisions = list(db.execute(text("SELECT version_num FROM alembic_version")).scalars())
            current_revision = revisions[0] if len(revisions) == 1 else None
            revision_state = "at_head" if current_revision == expected_head else "behind_or_diverged"
        return AdminDatabaseDiagnosticsRead(
            database="healthy",
            required_tables=required_tables,
            current_revision=current_revision,
            expected_head=expected_head,
            revision_state=revision_state,
        )
    except Exception as exc:
        db.rollback()
        if isinstance(exc, SQLAlchemyError):
            category = database_error_category(exc)
        else:
            category = "diagnostic_error"
        return AdminDatabaseDiagnosticsRead(
            database="unavailable",
            required_tables={name: False for name in required_table_names},
            current_revision=None,
            expected_head=expected_head,
            revision_state="unavailable",
            error_category=category,
        )


@router.get("/admin/users", response_model=AdminUsersRead, tags=["admin"])
def admin_list_users(
    q: str = Query(default="", max_length=200),
    account_status: str | None = Query(default=None, alias="status", pattern="^(active|disabled)$"),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> AdminUsersRead:
    filters = []
    if q.strip():
        term = q.strip().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{term}%"
        filters.append((User.email.ilike(pattern, escape="!")) | (User.display_name.ilike(pattern, escape="!")))
    if account_status == "active":
        filters.append(User.is_active.is_(True))
    elif account_status == "disabled":
        filters.append(User.is_active.is_(False))
    total = db.scalar(select(func.count()).select_from(User).where(*filters)) or 0
    users = db.scalars(
        select(User).where(*filters).order_by(User.created_at.desc(), User.id.desc()).offset(offset).limit(limit)
    ).all()
    admin_ids = _administrator_ids()
    return AdminUsersRead(
        items=[_admin_user_read(user, admin_ids) for user in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/admin/assets", response_model=AdminAssetsRead, tags=["admin"])
def admin_list_assets(
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> AdminAssetsRead:
    filters = []
    if q.strip():
        term = q.strip().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{term}%"
        filters.append((Asset.normalized_url.ilike(pattern, escape="!")) | User.email.ilike(pattern, escape="!"))
    total = db.scalar(
        select(func.count()).select_from(Asset).outerjoin(User, User.id == Asset.owner_id).where(*filters)
    ) or 0
    rows = db.execute(
        select(Asset, User.email)
        .outerjoin(User, User.id == Asset.owner_id)
        .where(*filters)
        .order_by(Asset.created_at.desc(), Asset.id.desc())
        .offset(offset).limit(limit)
    ).all()
    asset_ids = [asset.id for asset, _ in rows]
    scan_counts = dict(
        db.execute(
            select(Scan.asset_id, func.count())
            .join(Asset, and_(Asset.id == Scan.asset_id, Asset.owner_id == Scan.owner_id))
            .where(Scan.asset_id.in_(asset_ids))
            .group_by(Scan.asset_id)
        ).all()
    ) if asset_ids else {}
    latest_scan_id = (
        select(Scan.id)
        .where(Scan.asset_id == Asset.id, Scan.owner_id == Asset.owner_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).correlate(Asset).scalar_subquery()
    )
    latest_rows = db.execute(
        select(Asset.id, Scan.id, Scan.status, Scan.completed_at, Scan.created_at, Scan.error_message)
        .join(Scan, and_(Scan.id == latest_scan_id, Scan.owner_id == Asset.owner_id))
        .where(Asset.id.in_(asset_ids))
    ).all() if asset_ids else []
    latest_by_asset = {
        asset_id: (scan_id, scan_status, completed_at or created_at, error_message)
        for asset_id, scan_id, scan_status, completed_at, created_at, error_message in latest_rows
    }
    items = []
    for asset, owner_email in rows:
        latest = latest_by_asset.get(asset.id)
        items.append(AdminAssetRead(
            id=asset.id, target_url=asset.target_url, normalized_url=asset.normalized_url,
            owner_id=asset.owner_id, owner_email=owner_email,
            authorization_confirmed=asset.authorization_confirmed, created_at=asset.created_at,
            scan_count=scan_counts.get(asset.id, 0),
            latest_scan_id=latest[0] if latest else None,
            latest_scan_status=latest[1] if latest else None,
            latest_scan_at=latest[2] if latest else None,
            latest_scan_error=latest[3] if latest else None,
        ))
    return AdminAssetsRead(items=items, total=total, limit=limit, offset=offset)


@router.get("/admin/findings", response_model=AdminFindingsRead, tags=["admin"])
def admin_list_findings(
    q: str = Query(default="", max_length=200),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> AdminFindingsRead:
    filters = []
    if q.strip():
        term = q.strip().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{term}%"
        filters.append(
            Finding.title.ilike(pattern, escape="!")
            | Finding.evidence.ilike(pattern, escape="!")
            | Scan.target_url.ilike(pattern, escape="!")
            | User.email.ilike(pattern, escape="!")
        )
    if severity:
        filters.append(Finding.severity == severity)
    base = select(Finding).join(Scan, Scan.id == Finding.scan_id).outerjoin(User, User.id == Scan.owner_id).where(*filters)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    latest_verification_status = (
        select(VerificationAttempt.status)
        .where(VerificationAttempt.finding_id == Finding.id)
        .order_by(VerificationAttempt.created_at.desc(), VerificationAttempt.id.desc())
        .limit(1).correlate(Finding).scalar_subquery()
    )
    rows = db.execute(
        select(Finding, Scan, User.email, FindingRemediation.status, latest_verification_status)
        .join(Scan, Scan.id == Finding.scan_id)
        .outerjoin(User, User.id == Scan.owner_id)
        .outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
        .where(*filters)
        .order_by(case((Finding.severity == "critical", 0), (Finding.severity == "high", 1), (Finding.severity == "medium", 2), (Finding.severity == "low", 3), else_=4), Finding.id.desc())
        .offset(offset).limit(limit)
    ).all()
    finding_ids = [finding.id for finding, _, _, _, _ in rows]
    verification_counts = dict(
        db.execute(
            select(VerificationAttempt.finding_id, func.count())
            .where(VerificationAttempt.finding_id.in_(finding_ids))
            .group_by(VerificationAttempt.finding_id)
        ).all()
    ) if finding_ids else {}
    items = [AdminFindingRead(
        id=finding.id, stable_id=finding.stable_id, title=finding.title, severity=finding.severity,
        category=finding.category, evidence=finding.evidence, explanation=finding.explanation,
        remediation=finding.remediation, confidence=finding.confidence,
        evidence_data=json.loads(finding.evidence_data) if finding.evidence_data else None,
        dedup_key=finding.dedup_key, scan_id=scan.id, target_url=scan.target_url,
        owner_id=scan.owner_id, owner_email=owner_email,
        remediation_status=remediation_status or "open",
        verification_count=verification_counts.get(finding.id, 0),
        latest_verification_status=latest_status,
    ) for finding, scan, owner_email, remediation_status, latest_status in rows]
    return AdminFindingsRead(items=items, total=total, limit=limit, offset=offset)


@router.get("/admin/audit", response_model=list[AdminActivityRead], tags=["admin"])
def admin_audit(
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> list[AdminActivityRead]:
    query = select(ActivityEvent, User.email).outerjoin(User, User.id == ActivityEvent.owner_id)
    if q.strip():
        term = q.strip().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{term}%"
        query = query.where(
            ActivityEvent.event_type.ilike(pattern, escape="!")
            | ActivityEvent.summary.ilike(pattern, escape="!")
            | User.email.ilike(pattern, escape="!")
        )
    rows = db.execute(
        query.order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).offset(offset).limit(limit)
    ).all()
    return [
        AdminActivityRead(
            id=event.id, event_type=event.event_type, summary=event.summary,
            actor_user_id=event.owner_id if event.event_type.startswith("admin.") else None,
            actor_email=email if event.event_type.startswith("admin.") else None,
            owner_user_id=event.owner_id, owner_email=email, scan_id=event.scan_id,
            finding_id=event.finding_id, created_at=event.created_at,
        )
        for event, email in rows
    ]


def _require_admin_reauthentication(admin: User, current_password: str) -> None:
    if not verify_password(current_password, admin.password_hash):
        raise HTTPException(status_code=403, detail="Administrator re-authentication failed.")


@router.patch("/admin/users/{user_id}/status", response_model=AdminUserRead, tags=["admin"])
def admin_update_user_status(
    user_id: int,
    payload: AdminUserStatusUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _csrf: AuthSession = Depends(require_csrf),
) -> AdminUserRead:
    _require_admin_reauthentication(admin, payload.current_password)
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="The account was not found.")
    admin_ids = _administrator_ids()
    if target.is_active == payload.is_active:
        raise HTTPException(status_code=409, detail="The account already has the requested status.")
    if not payload.is_active and (target.id == admin.id or target.id in admin_ids):
        raise HTTPException(status_code=409, detail="Configured administrator accounts cannot be disabled here.")
    target.is_active = payload.is_active
    revoked_count = 0
    if not payload.is_active:
        revoked_count = db.execute(
            update(AuthSession)
            .where(AuthSession.user_id == target.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        ).rowcount or 0
    action = "enabled" if payload.is_active else "disabled"
    suffix = f"; revoked {revoked_count} active session(s)" if not payload.is_active else ""
    record_event(db, f"admin.user_{action}", f"Administrator {admin.id} {action} account {target.id}{suffix}.", owner_id=admin.id)
    db.commit()
    db.refresh(target)
    return _admin_user_read(target, admin_ids)


@router.post("/admin/users/{user_id}/sessions/revoke", tags=["admin"])
def admin_revoke_user_sessions(
    user_id: int,
    payload: AdminSessionRevokeRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _csrf: AuthSession = Depends(require_csrf),
) -> dict[str, int | str]:
    _require_admin_reauthentication(admin, payload.current_password)
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="The account was not found.")
    revoked_count = db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == target.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    ).rowcount or 0
    record_event(db, "admin.sessions_revoked", f"Administrator {admin.id} revoked {revoked_count} session(s) for account {target.id}.", owner_id=admin.id)
    db.commit()
    return {"message": "Active sessions were revoked.", "revoked_sessions": revoked_count}


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> ScanRead:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required before scanning.")
    asset = db.scalar(select(Asset).where(Asset.id == payload.asset_id, Asset.owner_id == user.id)) if payload.asset_id else None
    if payload.asset_id and asset is None:
        raise HTTPException(status_code=404, detail="The selected asset was not found.")
    if asset is not None and asset.normalized_url != payload.target_url:
        raise HTTPException(status_code=400, detail="The scan target does not match the selected asset.")
    scan = Scan(target_url=payload.target_url, normalized_url=payload.target_url, status="pending", asset_id=asset.id if asset else None, owner_id=user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    record_event(db, "scan.requested", f"Scan {scan.id} requested for the authorized target.", scan_id=scan.id, owner_id=user.id)
    db.commit()
    background_tasks.add_task(execute_scan, scan.id)
    return _scan_read(scan)


@router.get("/scans", response_model=ScanList, tags=["scans"])
def list_scans(q: str = Query(default="", max_length=200), scan_status: str | None = Query(default=None, alias="status", max_length=32), date_from: Date | None = None, date_to: Date | None = None, asset_id: int | None = Query(default=None, ge=1), limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanList:
    allowed_statuses = {"pending", "running", "completed", "partial", "failed"}
    if scan_status is not None and scan_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="The requested scan status filter is invalid.")
    filters = [Scan.owner_id == user.id]
    if q.strip():
        filters.append(Scan.target_url.ilike(f"%{q.strip()}%"))
    if scan_status:
        filters.append(Scan.status == scan_status)
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=400, detail="The scan date range is invalid.")
    if date_from:
        filters.append(Scan.created_at >= datetime.combine(date_from, time.min, tzinfo=UTC))
    if date_to:
        filters.append(Scan.created_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=UTC))
    if asset_id is not None:
        filters.append(Scan.asset_id == asset_id)
    total = db.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
    scans = db.scalars(select(Scan).where(*filters).order_by(Scan.created_at.desc(), Scan.id.desc()).offset(offset).limit(limit)).all()
    return ScanList(items=[_scan_read(scan) for scan in scans], total=total, limit=limit, offset=offset)


@router.get("/scans/compare", response_model=ScanComparisonRead, tags=["scans"])
def compare_scans(earlier_scan_id: int, later_scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanComparisonRead:
    if earlier_scan_id == later_scan_id:
        raise HTTPException(status_code=400, detail="Choose two different saved scans to compare.")
    scans = db.scalars(select(Scan).where(Scan.id.in_([earlier_scan_id, later_scan_id]), Scan.owner_id == user.id)).all()
    by_id = {scan.id: scan for scan in scans}
    earlier, later = by_id.get(earlier_scan_id), by_id.get(later_scan_id)
    if earlier is None or later is None:
        raise HTTPException(status_code=404, detail="Both scans must belong to your account.")
    if (earlier.normalized_url or earlier.target_url).rstrip("/").lower() != (later.normalized_url or later.target_url).rstrip("/").lower():
        raise HTTPException(status_code=400, detail="Scans can only be compared when they target the same normalized website.")
    if earlier.status not in {"completed", "partial"} or later.status not in {"completed", "partial"}:
        raise HTTPException(status_code=409, detail="Both scans must have persisted results before comparison.")

    def key(finding: Finding) -> str:
        return finding.dedup_key or finding.stable_id or f"{finding.category or 'general'}:{finding.title.strip().lower()}"

    earlier_findings = db.scalars(select(Finding).where(Finding.scan_id == earlier.id).order_by(Finding.id)).all()
    later_findings = db.scalars(select(Finding).where(Finding.scan_id == later.id).order_by(Finding.id)).all()

    old_groups: dict[str, list[Finding]] = defaultdict(list)
    for item in earlier_findings:
        old_groups[key(item)].append(item)

    new_groups: dict[str, list[Finding]] = defaultdict(list)
    for item in later_findings:
        new_groups[key(item)].append(item)

    def compared(finding: Finding, stable_id: str) -> ComparedFinding:
        return ComparedFinding(stable_id=stable_id, title=finding.title, severity=finding.severity)

    new_findings: list[ComparedFinding] = []
    no_longer_observed: list[ComparedFinding] = []
    still_present: list[ComparedFinding] = []
    severity_changes: list[SeverityChange] = []

    all_keys = set(old_groups.keys()) | set(new_groups.keys())
    for k in sorted(all_keys):
        olds = old_groups.get(k, [])
        news = new_groups.get(k, [])
        matched = min(len(olds), len(news))
        for i in range(matched):
            o, n = olds[i], news[i]
            ident = n.dedup_key or n.stable_id or k
            still_present.append(compared(n, ident))
            if o.severity != n.severity:
                severity_changes.append(SeverityChange(stable_id=ident, title=n.title, before=o.severity, after=n.severity))
        for o in olds[matched:]:
            ident = o.dedup_key or o.stable_id or k
            no_longer_observed.append(compared(o, ident))
        for n in news[matched:]:
            ident = n.dedup_key or n.stable_id or k
            new_findings.append(compared(n, ident))

    limitation = "A finding absent from the later scan is only no longer observed; it is not proof of remediation. Scan coverage, target behavior, and check completeness can differ. Risk scores summarize this scanner's recorded observations."
    if earlier.status == "partial" or later.status == "partial":
        limitation += " One or both scans were partial; unexecuted or skipped checks may account for differences."

    return ScanComparisonRead(
        earlier_scan_id=earlier.id,
        later_scan_id=later.id,
        target_url=earlier.normalized_url or earlier.target_url,
        risk_score_before=earlier.risk_score,
        risk_score_after=later.risk_score,
        risk_score_delta=later.risk_score - earlier.risk_score if earlier.risk_score is not None and later.risk_score is not None else None,
        new_findings=new_findings,
        no_longer_observed=no_longer_observed,
        still_present=still_present,
        severity_changes=severity_changes,
        limitation=limitation,
    )


@router.get("/scans/{scan_id}", response_model=ScanDetail, tags=["scans"])
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanDetail:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan was not found.")
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)).all()
    result = _scan_read(scan)
    return ScanDetail(
        **result.model_dump(),
        findings=[FindingRead(
            id=finding.id,
            stable_id=finding.stable_id,
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            evidence=finding.evidence,
            explanation=finding.explanation,
            remediation=finding.remediation,
            confidence=finding.confidence,
            evidence_data=json.loads(finding.evidence_data) if finding.evidence_data else None,
            dedup_key=finding.dedup_key,
        ) for finding in findings],
    )


@router.post("/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED, tags=["assets"])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> AssetRead:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required before registering an asset.")
    asset = Asset(target_url=payload.target_url, normalized_url=payload.target_url, authorization_confirmed=True, owner_id=user.id)
    db.add(asset)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An equivalent normalized asset is already registered.") from exc
    db.refresh(asset)
    record_event(db, "asset.registered", "An authorized website asset was registered.", scan_id=None, owner_id=user.id)
    db.commit()
    return AssetRead.model_validate(asset)


@router.get("/assets", response_model=list[AssetRead], tags=["assets"])
def list_assets(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[AssetRead]:
    return [AssetRead.model_validate(asset) for asset in db.scalars(select(Asset).where(Asset.owner_id == user.id).order_by(Asset.created_at.desc())).all()]


@router.get("/assets/overview", response_model=AssetOverviewRead, tags=["assets"])
def list_asset_overview(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> AssetOverviewRead:
    owner_scans = select(Scan).where(Scan.owner_id == user.id, Scan.asset_id == Asset.id)
    latest_id = owner_scans.with_only_columns(Scan.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    latest_status = owner_scans.with_only_columns(Scan.status).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    latest_time = owner_scans.with_only_columns(func.coalesce(Scan.completed_at, Scan.created_at)).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    latest_risk_score = owner_scans.with_only_columns(Scan.risk_score).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    latest_risk_level = owner_scans.with_only_columns(Scan.risk_level).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    latest_checks = owner_scans.with_only_columns(Scan.check_summary).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1).scalar_subquery()
    scan_count = select(func.count()).select_from(Scan).where(Scan.owner_id == user.id, Scan.asset_id == Asset.id).scalar_subquery()
    finding_count = select(func.count()).select_from(Finding).where(Finding.scan_id == latest_id).scalar_subquery()
    open_count = (
        select(func.count()).select_from(Finding).outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
        .where(Finding.scan_id == latest_id, func.coalesce(FindingRemediation.status, "open").in_(("open", "in_progress")))
        .scalar_subquery()
    )
    total = db.scalar(select(func.count()).select_from(Asset).where(Asset.owner_id == user.id)) or 0
    rows = db.execute(
        select(Asset, latest_id.label("latest_scan_id"), latest_status.label("latest_scan_status"), latest_time.label("last_scan_at"), latest_risk_score.label("latest_risk_score"), latest_risk_level.label("latest_risk_level"), latest_checks.label("latest_checks"), scan_count.label("scan_count"), finding_count.label("latest_findings"), open_count.label("latest_open_findings"))
        .where(Asset.owner_id == user.id).order_by(Asset.created_at.desc(), Asset.id.desc()).offset(offset).limit(limit)
    ).all()
    return AssetOverviewRead(
        items=[AssetSecurityRead(**AssetRead.model_validate(asset).model_dump(), latest_scan_id=latest_scan_id, latest_scan_status=latest_scan_status, last_scan_at=last_scan_at, latest_risk_score=latest_risk_score, latest_risk_level=latest_risk_level, latest_checks=_safe_check_summary(latest_checks), scan_count=scan_count, latest_findings=latest_findings, latest_open_findings=latest_open_findings) for asset, latest_scan_id, latest_scan_status, last_scan_at, latest_risk_score, latest_risk_level, latest_checks, scan_count, latest_findings, latest_open_findings in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/scans/{scan_id}/report.pdf", tags=["reports"])
def download_scan_report(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Response:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan was not found.")
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)).all()
    verification_attempts = db.scalars(
        select(VerificationAttempt).where(VerificationAttempt.scan_id == scan.id)
        .order_by(VerificationAttempt.created_at, VerificationAttempt.id)
    ).all()
    finding_ids = [f.id for f in findings]
    remediation_rows = db.execute(
        select(FindingRemediation.finding_id, FindingRemediation.status)
        .where(FindingRemediation.finding_id.in_(finding_ids))
    ).all() if finding_ids else []
    remediations = {row[0]: row[1] for row in remediation_rows}
    try:
        content = build_scan_pdf(scan, findings, verification_attempts, remediations=remediations)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="The report could not be generated from the saved scan.") from exc
    db.add(ReportMetadata(scan_id=scan.id, report_type="pdf"))
    record_event(db, "report.generated", f"A PDF report was generated for scan {scan.id}.", scan_id=scan.id, owner_id=user.id)
    _notify(db, user.id, "report.generated", "Assessment report generated", f"A PDF report was generated for scan {scan.id}.", scan_id=scan.id)
    db.commit()
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="sentinel-scan-{scan.id}.pdf"', "Cache-Control": "no-store"})


@router.get("/scans/{scan_id}/findings.csv", tags=["reports"])
def download_scan_findings_csv(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Response:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan was not found.")
    findings = db.execute(select(Finding, FindingRemediation.status).outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id).where(Finding.scan_id == scan.id).order_by(Finding.id)).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["scan_id", "target", "status", "risk_score", "finding_id", "stable_id", "title", "severity", "category", "confidence", "evidence", "explanation", "remediation", "remediation_status"])
    def safe_cell(value: object | None) -> str:
        text = "" if value is None else str(value)
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text
    for finding, remediation_status in findings:
        writer.writerow([safe_cell(value) for value in (scan.id, scan.target_url, scan.status, scan.risk_score, finding.id, finding.stable_id, finding.title, finding.severity, finding.category, finding.confidence, finding.evidence, finding.explanation, finding.remediation, remediation_status or "open")])
    db.add(ReportMetadata(scan_id=scan.id, report_type="csv"))
    record_event(db, "report.exported", f"A findings CSV export was generated for scan {scan.id}.", scan_id=scan.id, owner_id=user.id)
    _notify(db, user.id, "report.generated", "Findings CSV exported", f"A findings CSV export was generated for scan {scan.id}.", scan_id=scan.id)
    db.commit()
    return Response(content=output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="sentinel-scan-{scan.id}-findings.csv"', "Cache-Control": "no-store"})


@router.get("/reports", response_model=list[ReportHistoryRead], tags=["reports"])
def report_history(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[ReportHistoryRead]:
    rows = db.execute(select(ReportMetadata, Scan.target_url).join(Scan, Scan.id == ReportMetadata.scan_id).where(Scan.owner_id == user.id).order_by(ReportMetadata.created_at.desc(), ReportMetadata.id.desc()).offset(offset).limit(limit)).all()
    return [ReportHistoryRead(id=record.id, scan_id=record.scan_id, target_url=target_url, report_type=record.report_type, created_at=record.created_at) for record, target_url in rows]


@router.get("/findings/overview", response_model=list[FindingOverviewItem], tags=["findings"])
def findings_overview(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[FindingOverviewItem]:
    recent_scan_ids = select(Scan.id).where(Scan.owner_id == user.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(50).subquery()
    rows = db.execute(
        select(Finding, Scan, FindingRemediation.status)
        .join(Scan, Scan.id == Finding.scan_id)
        .outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
        .where(Scan.owner_id == user.id, Scan.id.in_(select(recent_scan_ids.c.id)))
        .order_by(Scan.created_at.desc(), Scan.id.desc(), Finding.id)
    ).all()
    return [FindingOverviewItem(
        id=finding.id, scan_id=scan.id, target_url=scan.target_url,
        stable_id=finding.stable_id, title=finding.title, severity=finding.severity,
        category=finding.category, evidence=finding.evidence, explanation=finding.explanation,
        remediation=finding.remediation, confidence=finding.confidence,
        evidence_data=json.loads(finding.evidence_data) if finding.evidence_data else None,
        dedup_key=finding.dedup_key, remediation_status=remediation_status or "open",
    ) for finding, scan, remediation_status in rows]


@router.get("/verification/overview", response_model=list[VerificationOverviewItem], tags=["verification"])
def verification_overview(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[VerificationOverviewItem]:
    recent_scan_ids = select(Scan.id).where(Scan.owner_id == user.id).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(50).subquery()
    rows = db.execute(
        select(Finding.id, Finding.scan_id, Scan.target_url, Finding.title, Finding.stable_id)
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.owner_id == user.id, Scan.id.in_(select(recent_scan_ids.c.id)))
        .order_by(Scan.created_at.desc(), Scan.id.desc(), Finding.id)
    ).all()
    finding_ids = [row.id for row in rows]
    attempts_by_finding: dict[int, list[VerificationAttemptRead]] = defaultdict(list)
    if finding_ids:
        attempts = db.scalars(
            select(VerificationAttempt)
            .where(VerificationAttempt.finding_id.in_(finding_ids))
            .order_by(VerificationAttempt.created_at.desc(), VerificationAttempt.id.desc())
        ).all()
        for attempt in attempts:
            attempts_by_finding[attempt.finding_id].append(VerificationAttemptRead.model_validate(attempt))
    return [VerificationOverviewItem(
        finding_id=row.id, scan_id=row.scan_id, target_url=row.target_url,
        title=row.title, stable_id=row.stable_id, attempts=attempts_by_finding[row.id],
    ) for row in rows]


@router.get("/findings/{finding_id}", response_model=FindingDetailRead, tags=["findings"])
def get_finding(finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> FindingDetailRead:
    row = db.execute(
        select(Finding, Scan, FindingRemediation.status)
        .join(Scan, Scan.id == Finding.scan_id)
        .outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id)
        .where(Finding.id == finding_id, Scan.owner_id == user.id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="The finding was not found.")
    finding, scan, remediation_status = row
    return FindingDetailRead(
        id=finding.id,
        scan_id=scan.id,
        target_url=scan.target_url,
        stable_id=finding.stable_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        evidence=finding.evidence,
        explanation=finding.explanation,
        remediation=finding.remediation,
        confidence=finding.confidence,
        evidence_data=json.loads(finding.evidence_data) if finding.evidence_data else None,
        dedup_key=finding.dedup_key,
        remediation_status=remediation_status or "open",
    )


@router.post("/findings/{finding_id}/verification", response_model=VerificationAttemptRead, status_code=status.HTTP_202_ACCEPTED, tags=["verification"])
def request_verification(finding_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> VerificationAttemptRead:
    finding = db.scalar(select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Finding.id == finding_id, Scan.owner_id == user.id))
    if finding is None:
        raise HTTPException(status_code=404, detail="The finding was not found.")
    scan = db.get(Scan, finding.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="The original scan was not found.")
    attempt = VerificationAttempt(scan_id=scan.id, finding_id=finding.id, status="pending", summary="Verification has been queued.")
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    record_event(db, "verification.requested", f"Verification was requested for finding {finding.id}.", scan_id=scan.id, finding_id=finding.id, owner_id=user.id)
    db.commit()
    background_tasks.add_task(execute_verification, attempt.id)
    return VerificationAttemptRead.model_validate(attempt)


@router.get("/findings/{finding_id}/verification", response_model=list[VerificationAttemptRead], tags=["verification"])
def list_verifications(finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[VerificationAttemptRead]:
    if db.scalar(select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Finding.id == finding_id, Scan.owner_id == user.id)) is None:
        raise HTTPException(status_code=404, detail="The finding was not found.")
    attempts = db.scalars(select(VerificationAttempt).where(VerificationAttempt.finding_id == finding_id).order_by(VerificationAttempt.created_at.desc())).all()
    return [VerificationAttemptRead.model_validate(attempt) for attempt in attempts]


@router.get("/activity", response_model=list[ActivityEventRead], tags=["activity"])
def list_activity(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[ActivityEventRead]:
    events = db.scalars(select(ActivityEvent).where(ActivityEvent.owner_id == user.id).order_by(ActivityEvent.created_at.desc()).offset(offset).limit(limit)).all()
    return [ActivityEventRead.model_validate(event) for event in events]


@router.get("/remediation", response_model=list[RemediationRead], tags=["remediation"])
def list_remediation(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[RemediationRead]:
    rows = db.execute(select(Finding, Scan, FindingRemediation).join(Scan, Scan.id == Finding.scan_id).outerjoin(FindingRemediation, FindingRemediation.finding_id == Finding.id).where(Scan.owner_id == user.id).order_by(case((Finding.severity == "critical", 0), (Finding.severity == "high", 1), (Finding.severity == "medium", 2), (Finding.severity == "low", 3), else_=4), Finding.id.desc())).all()
    return [RemediationRead(finding_id=finding.id, scan_id=scan.id, target_url=scan.target_url, title=finding.title, severity=finding.severity, remediation=finding.remediation, status=state.status if state else "open", updated_at=state.updated_at if state else None) for finding, scan, state in rows]


@router.patch("/findings/{finding_id}/remediation", response_model=RemediationRead, tags=["remediation"])
def update_remediation(finding_id: int, payload: RemediationUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> RemediationRead:
    finding = db.scalar(select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Finding.id == finding_id, Scan.owner_id == user.id))
    if finding is None:
        raise HTTPException(status_code=404, detail="The finding was not found.")
    scan = db.get(Scan, finding.scan_id)
    state = db.get(FindingRemediation, finding.id)
    previous = state.status if state else "open"
    allowed = {
        "open": {"in_progress", "accepted_risk"},
        "in_progress": {"open", "fixed", "accepted_risk"},
        "fixed": {"open", "in_progress"},
        "accepted_risk": {"open", "in_progress"},
    }
    if payload.status != previous and payload.status not in allowed[previous]:
        raise HTTPException(status_code=409, detail=f"Remediation cannot transition from {previous.replace('_', ' ')} to {payload.status.replace('_', ' ')}.")
    if payload.status != previous:
        if state is None:
            state = FindingRemediation(finding_id=finding.id, owner_id=user.id, status=payload.status, updated_by=user.id)
            db.add(state)
        else:
            state.status = payload.status
            state.updated_by = user.id
            state.updated_at = datetime.now(UTC)
        db.add(RemediationChange(finding_id=finding.id, owner_id=user.id, from_status=previous, to_status=payload.status, changed_by=user.id))
        record_event(db, "remediation.updated", f"Finding {finding.id} remediation changed from {previous} to {payload.status}.", scan_id=scan.id, finding_id=finding.id, owner_id=user.id)
        _notify(db, user.id, "remediation.updated", "Remediation status updated", f"{finding.title}: {previous.replace('_', ' ')} → {payload.status.replace('_', ' ')}.", scan_id=scan.id, finding_id=finding.id)
        db.commit()
        db.refresh(state)
    return RemediationRead(finding_id=finding.id, scan_id=scan.id, target_url=scan.target_url, title=finding.title, severity=finding.severity, remediation=finding.remediation, status=state.status if state else previous, updated_at=state.updated_at if state else None)


@router.get("/findings/{finding_id}/remediation/history", response_model=list[RemediationChangeRead], tags=["remediation"])
def list_remediation_history(finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[RemediationChangeRead]:
    if db.scalar(select(Finding.id).join(Scan, Scan.id == Finding.scan_id).where(Finding.id == finding_id, Scan.owner_id == user.id)) is None:
        raise HTTPException(status_code=404, detail="The finding was not found.")
    history = db.scalars(select(RemediationChange).where(RemediationChange.finding_id == finding_id, RemediationChange.owner_id == user.id).order_by(RemediationChange.created_at.desc(), RemediationChange.id.desc())).all()
    return [RemediationChangeRead.model_validate(entry) for entry in history]


@router.get("/notifications", response_model=list[NotificationRead], tags=["notifications"])
def list_notifications(limit: int = Query(default=30, ge=1, le=100), db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[NotificationRead]:
    rows = db.scalars(select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc(), Notification.id.desc()).limit(limit)).all()
    return [NotificationRead.model_validate(row) for row in rows]


@router.patch("/notifications/{notification_id}/read", response_model=NotificationRead, tags=["notifications"])
def mark_notification_read(notification_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user), _csrf: AuthSession = Depends(require_csrf)) -> NotificationRead:
    notification = db.scalar(select(Notification).where(Notification.id == notification_id, Notification.user_id == user.id))
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification was not found.")
    if notification.read_at is None:
        notification.read_at = datetime.now(UTC)
        db.commit()
        db.refresh(notification)
    return NotificationRead.model_validate(notification)
