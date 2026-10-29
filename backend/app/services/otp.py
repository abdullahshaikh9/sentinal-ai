"""Provider-backed OTP generation, storage helpers, and delivery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import base64
from email.utils import formataddr, parseaddr
import hashlib
import hmac
import logging
import secrets
import smtplib
import sys
from email.message import EmailMessage

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import OtpChallenge, OtpSendAttempt, User


console_sms_logger = logging.getLogger("sentinel.otp.sms.console")
delivery_logger = logging.getLogger("sentinel.otp.delivery")
_CONSOLE_SMS_HANDLER_MARKER = "_sentinel_console_sms_terminal"


class OtpDeliveryError(RuntimeError):
    """Safe provider-independent delivery failure."""


class OtpSendRateLimitError(RuntimeError):
    """Raised when recipient or client-IP OTP send limits have been reached."""


class _CurrentStderr:
    """Resolve stderr at write time so the dedicated handler follows server/test streams."""

    @staticmethod
    def write(message: str) -> int:
        return sys.stderr.write(message)

    @staticmethod
    def flush() -> None:
        sys.stderr.flush()


def normalize_phone(phone_number: str) -> str:
    return "".join(phone_number.split()).replace("(", "").replace(")", "").replace("-", "")


def email_provider_configured(settings: Settings) -> bool:
    smtp_auth_configured = bool(settings.smtp_username and settings.smtp_password)
    smtp_auth_partial = bool(settings.smtp_username) != bool(settings.smtp_password)
    return bool(
        settings.email_provider.lower() == "smtp"
        and all((settings.smtp_host, settings.smtp_from, settings.otp_pepper))
        and not smtp_auth_partial
        and (not settings.smtp_host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"} or smtp_auth_configured)
    )


def sms_provider_configured(settings: Settings) -> bool:
    sms_provider = settings.sms_provider.lower()
    return bool((
        sms_provider == "twilio" and all((settings.sms_account_sid, settings.sms_auth_token, settings.sms_from_number, settings.otp_pepper))
    ) or (
        sms_provider == "console" and settings.app_env.lower() == "development" and bool(settings.otp_pepper)
    ) or (
        sms_provider == "textbee" and settings.textbee_enabled and bool(settings.textbee_api_key and settings.otp_pepper)
    ))


def providers_configured(settings: Settings) -> bool:
    return email_provider_configured(settings) and sms_provider_configured(settings)


def configuration_message(settings: Settings) -> str:
    if not settings.otp_pepper:
        return "OTP verification is unavailable until OTP_PEPPER is configured."
    if settings.email_provider.lower() != "smtp" or not all((settings.smtp_host, settings.smtp_from)):
        return "Email verification is unavailable until the SMTP provider is configured."
    smtp_auth_configured = bool(settings.smtp_username and settings.smtp_password)
    smtp_auth_partial = bool(settings.smtp_username) != bool(settings.smtp_password)
    if smtp_auth_partial or (settings.smtp_host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"} and not smtp_auth_configured):
        return "Email verification is unavailable until both SMTP_USERNAME and SMTP_PASSWORD are configured."
    sms_provider = settings.sms_provider.lower()
    if sms_provider == "console" and settings.app_env.lower() != "development":
        return "SMS_PROVIDER=console is only permitted when APP_ENV=development."
    if sms_provider == "console" and not settings.otp_pepper:
        return "OTP verification is unavailable until OTP_PEPPER is configured."
    if sms_provider not in {"twilio", "console"}:
        if sms_provider == "textbee":
            if not settings.textbee_enabled:
                return "TextBee SMS is disabled. Set TEXTBEE_ENABLED=true to enable mobile verification."
            if not settings.textbee_api_key:
                return "TextBee SMS is not configured. Set TEXTBEE_API_KEY in the backend environment."
            return "TextBee SMS is not configured. Ensure OTP_PEPPER is set."
        return "Mobile verification is unavailable until the SMS provider is configured."
    if sms_provider == "twilio" and not all((settings.sms_account_sid, settings.sms_auth_token, settings.sms_from_number)):
        return "Mobile verification is unavailable until the SMS provider is configured."
    return ""


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _hash_code(code: str, salt: bytes, pepper: str) -> str:
    return hmac.new(pepper.encode(), salt + code.encode(), hashlib.sha256).hexdigest()


def create_challenge(db: Session, user: User, channel: str, registration_token_hash: str, settings: Settings) -> tuple[OtpChallenge, str]:
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_bytes(16)
    now = datetime.now(UTC)
    challenge = OtpChallenge(
        user_id=user.id,
        channel=channel,
        registration_token_hash=registration_token_hash,
        code_hash=_hash_code(code, salt, settings.otp_pepper or ""),
        code_salt=_encode(salt),
        expires_at=now + timedelta(minutes=settings.otp_ttl_minutes),
        last_sent_at=now,
    )
    db.add(challenge)
    delivery_logger.info("OTP challenge created channel=%s user_id=%s expires_in_minutes=%s", channel, user.id, settings.otp_ttl_minutes)
    return challenge, code


def verify_code(challenge: OtpChallenge, code: str, settings: Settings) -> bool:
    try:
        salt = base64.urlsafe_b64decode(challenge.code_salt.encode())
    except ValueError:
        return False
    return hmac.compare_digest(challenge.code_hash, _hash_code(code, salt, settings.otp_pepper or ""))


def deliver_email_otp(user: User, code: str, settings: Settings) -> None:
    if settings.email_provider.lower() != "smtp" or not settings.smtp_host or not settings.smtp_from:
        raise RuntimeError("Email verification provider is not configured.")
    _, sender_email = parseaddr(settings.smtp_from.strip())
    if not sender_email or "@" not in sender_email:
        raise RuntimeError("SMTP_FROM must contain the configured sender email address.")
    message = EmailMessage()
    message["From"] = formataddr(("Sentinel AI", sender_email))
    message["To"] = user.email
    message["Subject"] = "Your Sentinel AI Verification Code"
    message.set_content(
        "Hello,\n\n"
        f"Your verification code for Sentinel AI is: {code}\n\n"
        f"This code expires in {settings.otp_ttl_minutes} minutes. Do not share it with anyone.\n\n"
        "If you did not request this code, you can ignore this message.\n\n"
        "— Sentinel AI Security Team"
    )
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.sms_timeout_seconds) as server:
        if settings.smtp_use_tls:
            server.starttls()
        if settings.smtp_username and settings.smtp_password:
            password = settings.smtp_password
            if settings.smtp_host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"}:
                password = "".join(password.split())
            server.login(settings.smtp_username, password)
        server.send_message(message)


def deliver_sms_otp(user: User, code: str, settings: Settings) -> None:
    sms_provider = settings.sms_provider.lower()
    if sms_provider == "console":
        if settings.app_env.lower() != "development":
            raise RuntimeError("SMS_PROVIDER=console is only permitted when APP_ENV=development.")
        if not settings.otp_pepper:
            raise RuntimeError("OTP_PEPPER is required for mobile verification.")
        _configure_console_sms_logger()
        console_sms_logger.info("Development mobile OTP generated for user_id=%s phone=%s code=%s", user.id, _mask_phone(user.phone_number), code)
        return
    if sms_provider == "textbee":
        if not settings.textbee_enabled:
            raise RuntimeError("TextBee SMS is disabled.")
        if not settings.textbee_api_key or not settings.otp_pepper:
            raise RuntimeError("TextBee SMS is not configured.")
        if not user.phone_number:
            raise RuntimeError("A mobile number is not available for SMS delivery.")
        response = httpx.post(
            "https://api.textbee.dev/api/v1/gateway/send-sms",
            headers={"x-api-key": settings.textbee_api_key, "Content-Type": "application/json"},
            json={
                "recipients": [normalize_phone(user.phone_number)],
                "message": f"Sentinel AI verification code: {code}. Expires in {settings.otp_ttl_minutes} minutes. Do not share this code.",
            },
            timeout=settings.sms_timeout_seconds,
        )
        response.raise_for_status()
        try:
            result = response.json()
        except ValueError as exc:
            raise RuntimeError("TextBee returned an unreadable response.") from exc
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict) or data.get("success") is not True or not isinstance(data.get("smsBatchId"), str) or not data["smsBatchId"] or data.get("recipientCount") != 1:
            raise RuntimeError("TextBee did not confirm acceptance of the SMS request.")
        delivery_logger.info("TextBee accepted OTP SMS request user_id=%s status_code=%s", user.id, response.status_code)
        return
    if sms_provider != "twilio" or not settings.sms_account_sid or not settings.sms_auth_token or not settings.sms_from_number:
        raise RuntimeError("SMS verification provider is not configured.")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.sms_account_sid}/Messages.json"
    response = httpx.post(url, data={"From": settings.sms_from_number, "To": user.phone_number, "Body": f"Sentinel AI verification code: {code}. Expires in {settings.otp_ttl_minutes} minutes. Do not share this code."}, auth=(settings.sms_account_sid, settings.sms_auth_token), timeout=settings.sms_timeout_seconds)
    response.raise_for_status()


def deliver(channel: str, user: User, code: str, settings: Settings) -> None:
    provider = settings.email_provider if channel == "email" else settings.sms_provider
    delivery_logger.info("OTP provider selected channel=%s provider=%s user_id=%s", channel, provider, user.id)
    delivery_logger.info("OTP delivery started channel=%s provider=%s user_id=%s", channel, provider, user.id)
    try:
        if channel == "email":
            deliver_email_otp(user, code, settings)
        elif channel == "phone":
            deliver_sms_otp(user, code, settings)
        else:
            raise RuntimeError("Unsupported OTP delivery channel.")
        delivery_logger.info("OTP submission accepted channel=%s provider=%s user_id=%s", channel, provider, user.id)
    except Exception as exc:
        raise OtpDeliveryError(f"{channel} OTP delivery failed.") from exc


def log_delivery_failure(channel: str, settings: Settings, error: Exception) -> None:
    provider = settings.email_provider if channel == "email" else settings.sms_provider
    cause = error.__cause__
    cause_type = type(cause).__name__ if cause is not None else type(error).__name__
    response = getattr(cause, "response", None)
    status_code = getattr(response, "status_code", None)
    delivery_logger.error("OTP delivery failed channel=%s provider=%s error_type=%s cause_type=%s status_code=%s", channel, provider, type(error).__name__, cause_type, status_code if isinstance(status_code, int) else "none")


def _mask_phone(phone_number: str | None) -> str:
    if not phone_number:
        return "<redacted>"
    return f"{'*' * max(0, len(phone_number) - 4)}{phone_number[-4:]}"


def _configure_console_sms_logger() -> None:
    """Write development SMS OTP records to the backend terminal despite Uvicorn's config."""
    if not any(getattr(handler, _CONSOLE_SMS_HANDLER_MARKER, False) for handler in console_sms_logger.handlers):
        handler = logging.StreamHandler(_CurrentStderr())
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        setattr(handler, _CONSOLE_SMS_HANDLER_MARKER, True)
        console_sms_logger.addHandler(handler)
    console_sms_logger.setLevel(logging.INFO)
    console_sms_logger.propagate = False


def get_challenge(db: Session, token_hash: str, channel: str) -> OtpChallenge | None:
    return db.scalar(select(OtpChallenge).where(OtpChallenge.registration_token_hash == token_hash, OtpChallenge.channel == channel).order_by(OtpChallenge.created_at.desc(), OtpChallenge.id.desc()))


def _rate_subject_hash(value: str, settings: Settings) -> str:
    return hmac.new((settings.otp_pepper or "").encode(), value.strip().lower().encode(), hashlib.sha256).hexdigest()


def check_send_rate_limits(db: Session, recipients: list[str], client_ip: str, settings: Settings) -> None:
    """Check per-recipient and per-IP hourly limits using keyed, non-reversible identifiers."""
    now = datetime.now(UTC)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)
    db.execute(delete(OtpSendAttempt).where(OtpSendAttempt.created_at < day_ago))
    ip_hash = _rate_subject_hash(client_ip or "unknown", settings)
    ip_count = db.scalar(select(func.count()).select_from(OtpSendAttempt).where(OtpSendAttempt.ip_hash == ip_hash, OtpSendAttempt.created_at >= hour_ago)) or 0
    unique_recipients = {_rate_subject_hash(recipient, settings) for recipient in recipients}
    if ip_count + len(unique_recipients) > settings.otp_max_sends_per_ip_per_hour:
        raise OtpSendRateLimitError("Too many verification messages have been requested. Try again later.")
    for recipient_hash in unique_recipients:
        count = db.scalar(select(func.count()).select_from(OtpSendAttempt).where(OtpSendAttempt.recipient_hash == recipient_hash, OtpSendAttempt.created_at >= hour_ago)) or 0
        if count >= settings.otp_max_sends_per_recipient_per_hour:
            raise OtpSendRateLimitError("Too many verification messages have been requested. Try again later.")


def record_send_attempts(db: Session, recipients: list[str], client_ip: str, settings: Settings) -> None:
    ip_hash = _rate_subject_hash(client_ip or "unknown", settings)
    for recipient_hash in {_rate_subject_hash(recipient, settings) for recipient in recipients}:
        db.add(OtpSendAttempt(recipient_hash=recipient_hash, ip_hash=ip_hash))
