"""Session authentication and scrypt password hashing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import base64
import hashlib
import hmac
import secrets

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import AuthSession, LoginAttempt, LoginRateLimitMutex, User


_SALT_BYTES = 16
_KEY_BYTES = 32
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_MAX_FAILURES = 5
_WINDOW = timedelta(minutes=10)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_BYTES)
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${encode(salt)}${encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_encoded, digest_encoded = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_encoded.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_encoded.encode("ascii"))
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _rate_keys(request: Request, email: str) -> tuple[str, str, str]:
    host = request.client.host if request.client else "unknown"
    normalized_email = normalize_email(email)
    pepper = get_settings().otp_pepper
    digest = lambda value: hmac.new(pepper.encode(), value.encode(), hashlib.sha256).hexdigest() if pepper else hashlib.sha256(value.encode()).hexdigest()
    return (
        digest(f"pair:{host}:{normalized_email}"),
        digest(f"account:{normalized_email}"),
        digest(f"ip:{host}"),
    )


def _acquire_rate_limit_mutex(db: Session) -> None:
    dialect = db.get_bind().dialect.name
    if dialect == "mysql":
        statement = mysql_insert(LoginRateLimitMutex).values(id=1).on_duplicate_key_update(id=1)
    elif dialect == "sqlite":
        statement = sqlite_insert(LoginRateLimitMutex).values(id=1).on_conflict_do_nothing(index_elements=["id"])
    else:
        raise RuntimeError("Login rate limiting requires the configured MySQL or SQLite database.")
    db.execute(statement)
    # The write lock is held only during reservation/finalization. It serializes
    # admission across workers and SQLite test clients without locking during
    # password hashing.
    db.execute(update(LoginRateLimitMutex).where(LoginRateLimitMutex.id == 1).values(id=LoginRateLimitMutex.id))


def reserve_login_attempt(request: Request, email: str, db: Session) -> tuple[str, tuple[str, str, str]]:
    """Atomically reserve a slot across account, client, and account/client limits."""
    db.commit()
    now = datetime.now(UTC)
    keys = _rate_keys(request, email)
    attempt_id = secrets.token_hex(32)
    try:
        _acquire_rate_limit_mutex(db)
        db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < now - _WINDOW))
        counts = db.execute(
            select(LoginAttempt.attempt_key, func.count())
            .where(LoginAttempt.attempt_key.in_(keys), LoginAttempt.created_at >= now - _WINDOW)
            .group_by(LoginAttempt.attempt_key)
        ).all()
        if any(count >= _MAX_FAILURES for _, count in counts):
            db.rollback()
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        db.add_all(LoginAttempt(attempt_id=attempt_id, attempt_key=key, state="in_flight", created_at=now) for key in keys)
        db.commit()
        return attempt_id, keys
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise


def finalize_login_attempt(
    reservation: tuple[str, tuple[str, str, str]],
    db: Session,
    *,
    outcome: str,
) -> None:
    """Commit a failed attempt or release a successful/inactive request reservation."""
    attempt_id, keys = reservation
    if outcome not in {"failed", "success", "release"}:
        raise ValueError("Unsupported login rate-limit outcome.")
    db.commit()
    try:
        _acquire_rate_limit_mutex(db)
        reservation_rows = db.query(LoginAttempt).filter(LoginAttempt.attempt_id == attempt_id)
        if outcome == "failed":
            reservation_rows.update({LoginAttempt.state: "failed", LoginAttempt.created_at: datetime.now(UTC)}, synchronize_session=False)
        else:
            reservation_rows.delete(synchronize_session=False)
            if outcome == "success":
                pair_key, account_key, _ = keys
                db.execute(
                    delete(LoginAttempt).where(
                        LoginAttempt.attempt_key.in_((pair_key, account_key)),
                        LoginAttempt.state == "failed",
                    )
                )
        db.commit()
    except Exception:
        db.rollback()
        raise


def clear_login_failures(request: Request, email: str, db: Session) -> None:
    pair_key, account_key, _ = _rate_keys(request, email)
    db.commit()
    try:
        _acquire_rate_limit_mutex(db)
        db.execute(
            delete(LoginAttempt).where(
                LoginAttempt.attempt_key.in_((pair_key, account_key)),
                LoginAttempt.state == "failed",
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def create_session(db: Session, user: User) -> tuple[str, str, AuthSession]:
    raw_token = secrets.token_urlsafe(32)
    raw_csrf = secrets.token_urlsafe(32)
    session = AuthSession(
        user_id=user.id,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        csrf_token_hash=hashlib.sha256(raw_csrf.encode()).hexdigest(),
        expires_at=datetime.now(UTC) + timedelta(minutes=get_settings().session_ttl_minutes),
    )
    db.add(session)
    db.flush()
    return raw_token, raw_csrf, session


def get_current_session(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    raw_token = request.cookies.get(get_settings().auth_cookie_name)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication is required.")
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash, AuthSession.revoked_at.is_(None)))
    expires_at = session.expires_at.replace(tzinfo=UTC) if session is not None and session.expires_at.tzinfo is None else (session.expires_at if session is not None else None)
    if session is None or expires_at <= datetime.now(UTC):
        if session is not None:
            session.revoked_at = datetime.now(UTC)
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session has expired. Please sign in again.")
    return session


def get_current_session_read_only(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    """Authenticate without revoking expired sessions or committing any state."""
    raw_token = request.cookies.get(get_settings().auth_cookie_name)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication is required.")
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash, AuthSession.revoked_at.is_(None)))
    expires_at = session.expires_at.replace(tzinfo=UTC) if session is not None and session.expires_at.tzinfo is None else (session.expires_at if session is not None else None)
    if session is None or expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session has expired. Please sign in again.")
    return session


def get_current_user(session: AuthSession = Depends(get_current_session), db: Session = Depends(get_db)) -> User:
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your account is unavailable.")
    if user.email_verified_at is None or user.phone_verified_at is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email and mobile verification are required before account access.")
    return user


def get_current_user_read_only(session: AuthSession = Depends(get_current_session_read_only), db: Session = Depends(get_db)) -> User:
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your account is unavailable.")
    if user.email_verified_at is None or user.phone_verified_at is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email and mobile verification are required before account access.")
    return user


def require_csrf(request: Request, session: AuthSession = Depends(get_current_session)) -> AuthSession:
    csrf_cookie = request.cookies.get(get_settings().csrf_cookie_name)
    csrf_header = request.headers.get("X-CSRF-Token")
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    expected = hashlib.sha256(csrf_cookie.encode()).hexdigest()
    if not hmac.compare_digest(expected, session.csrf_token_hash):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    return session


def require_csrf_read_only(request: Request, session: AuthSession = Depends(get_current_session_read_only)) -> AuthSession:
    csrf_cookie = request.cookies.get(get_settings().csrf_cookie_name)
    csrf_header = request.headers.get("X-CSRF-Token")
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    expected = hashlib.sha256(csrf_cookie.encode()).hexdigest()
    if not hmac.compare_digest(expected, session.csrf_token_hash):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    return session


def set_auth_cookies(response, raw_token: str, raw_csrf: str) -> None:
    settings = get_settings()
    response.set_cookie(settings.auth_cookie_name, raw_token, httponly=True, secure=settings.secure_auth_cookies, samesite="none" if settings.secure_auth_cookies else "lax", max_age=settings.session_ttl_minutes * 60, path="/")
    response.set_cookie(settings.csrf_cookie_name, raw_csrf, httponly=False, secure=settings.secure_auth_cookies, samesite="none" if settings.secure_auth_cookies else "lax", max_age=settings.session_ttl_minutes * 60, path="/")


def clear_auth_cookies(response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.auth_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
