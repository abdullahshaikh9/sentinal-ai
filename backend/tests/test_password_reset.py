from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import ActivityEvent, AuthSession, PasswordResetChallenge, User
from app.config import Settings
import app.api.routes as routes
from app.services.auth import hash_password, verify_password
from app.services import otp


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    delivered_reset_codes: list[tuple[str, str]] = []

    def fake_deliver_reset(user: User, code: str, settings: Settings):
        delivered_reset_codes.append((user.email, code))

    test_settings = Settings(
        _env_file=None,
        ai_provider="none",
        ai_api_key=None,
        gemini_api_key=None,
        email_provider="smtp",
        smtp_host="smtp.test.local",
        smtp_from="security@sentinel.test",
        sms_provider="console",
        otp_pepper="test-pepper-12345",
        otp_ttl_minutes=5,
        otp_max_attempts=5,
        otp_resend_cooldown_seconds=60,
    )

    monkeypatch.setattr(routes, "get_settings", lambda: test_settings)
    monkeypatch.setattr(otp, "deliver_password_reset_otp", fake_deliver_reset)
    monkeypatch.setattr(routes, "deliver_password_reset_otp", fake_deliver_reset)
    app.dependency_overrides[get_db] = override_db

    with TestClient(app) as test_client:
        yield test_client, factory, delivered_reset_codes

    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def _create_verified_user(factory: sessionmaker[Session], email="user@example.test", password="OldPassword123") -> User:
    with factory() as db:
        user = User(
            email=email,
            display_name="Test User",
            phone_number="+15551234567",
            password_hash=hash_password(password),
            email_verified_at=datetime.now(UTC),
            phone_verified_at=datetime.now(UTC),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def test_password_reset_happy_path(client) -> None:
    test_client, factory, delivered = client
    user = _create_verified_user(factory, email="alice@example.test", password="OldPassword123")

    # 1. User signs in and has an active session
    login_resp = test_client.post("/api/v1/auth/login", json={"email": "alice@example.test", "password": "OldPassword123"})
    assert login_resp.status_code == 200
    session_cookies = login_resp.cookies

    # Confirm session works
    me_resp = test_client.get("/api/v1/auth/me", cookies=session_cookies)
    assert me_resp.status_code == 200

    # 2. Request password reset
    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "alice@example.test"})
    assert req_resp.status_code == 200
    req_data = req_resp.json()
    assert "If an account exists with that email" in req_data["message"]
    assert "reset_token" in req_data
    reset_token = req_data["reset_token"]

    # Email delivered via mock
    assert len(delivered) == 1
    assert delivered[0][0] == "alice@example.test"
    code = delivered[0][1]
    assert len(code) == 6

    # 3. Verify OTP code
    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": code})
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert "password_reset_token" in verify_data
    password_reset_token = verify_data["password_reset_token"]

    # 4. Reset password to new password
    reset_resp = test_client.post("/api/v1/auth/reset-password", json={
        "password_reset_token": password_reset_token,
        "new_password": "NewStrongPassword456",
    })
    assert reset_resp.status_code == 200
    assert "Your password has been reset successfully" in reset_resp.json()["message"]

    # 5. Requirement 5: Previous session must now be revoked
    me_after = test_client.get("/api/v1/auth/me", cookies=session_cookies)
    assert me_after.status_code == 401

    # 6. Cannot sign in with old password
    old_login = test_client.post("/api/v1/auth/login", json={"email": "alice@example.test", "password": "OldPassword123"})
    assert old_login.status_code == 401

    # 7. Can sign in with new password
    new_login = test_client.post("/api/v1/auth/login", json={"email": "alice@example.test", "password": "NewStrongPassword456"})
    assert new_login.status_code == 200
    assert new_login.json()["user"]["email"] == "alice@example.test"


def test_password_reset_email_enumeration_protection(client) -> None:
    test_client, factory, delivered = client

    # Request reset for an email that definitely does not exist
    response = test_client.post("/api/v1/auth/forgot-password", json={"email": "nonexistent@example.test"})
    assert response.status_code == 200
    data = response.json()
    assert "If an account exists with that email" in data["message"]
    assert "reset_token" in data
    # No email should be sent
    assert len(delivered) == 0

    # Submitting any code for this dummy token fails with generic invalid message
    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": data["reset_token"], "code": "123456"})
    assert verify_resp.status_code == 400
    assert "invalid or expired" in verify_resp.json()["detail"].lower()


def test_password_reset_invalid_code_and_attempt_counter(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="bob@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "bob@example.test"})
    reset_token = req_resp.json()["reset_token"]
    assert len(delivered) == 1
    correct_code = delivered[0][1]

    # Submit invalid code
    bad_code = "000000" if correct_code != "000000" else "111111"
    verify_bad = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": bad_code})
    assert verify_bad.status_code == 400
    assert "incorrect" in verify_bad.json()["detail"].lower()

    # Verify attempt count incremented in DB
    with factory() as db:
        ch = db.scalar(select(PasswordResetChallenge).where(PasswordResetChallenge.user_id != 0))
        assert ch.attempts == 1


def test_password_reset_exhausted_attempts(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="charlie@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "charlie@example.test"})
    reset_token = req_resp.json()["reset_token"]
    correct_code = delivered[0][1]

    # Submit 5 incorrect codes
    for _ in range(5):
        test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": "999999"})

    # Even with correct code, now rejected as exhausted
    exhausted_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": correct_code})
    assert exhausted_resp.status_code == 400
    assert "expired or has too many failed attempts" in exhausted_resp.json()["detail"].lower()


def test_password_reset_expired_code(client) -> None:
    test_client, factory, delivered = client
    user = _create_verified_user(factory, email="david@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "david@example.test"})
    reset_token = req_resp.json()["reset_token"]
    code = delivered[0][1]

    # Force challenge to expired in DB
    with factory() as db:
        db.execute(
            update(PasswordResetChallenge)
            .where(PasswordResetChallenge.user_id == user.id)
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        db.commit()

    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": code})
    assert verify_resp.status_code == 400
    assert "expired or has too many failed attempts" in verify_resp.json()["detail"].lower()


def test_password_reset_single_use_token_cannot_be_reused(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="eve@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "eve@example.test"})
    reset_token = req_resp.json()["reset_token"]
    code = delivered[0][1]

    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": code})
    password_reset_token = verify_resp.json()["password_reset_token"]

    # First reset succeeds
    reset_1 = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": password_reset_token, "new_password": "NewPassword123A"})
    assert reset_1.status_code == 200

    # Second reset with same token fails (single use!)
    reset_2 = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": password_reset_token, "new_password": "NewPassword123B"})
    assert reset_2.status_code == 400
    assert "already been used" in reset_2.json()["detail"].lower()


def test_password_reset_code_cannot_be_verified_twice(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="replay@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "replay@example.test"})
    reset_token = req_resp.json()["reset_token"]
    code = delivered[0][1]

    first_verify = test_client.post(
        "/api/v1/auth/verify-reset-code",
        json={"reset_token": reset_token, "code": code},
    )
    assert first_verify.status_code == 200

    replay_verify = test_client.post(
        "/api/v1/auth/verify-reset-code",
        json={"reset_token": reset_token, "code": code},
    )
    assert replay_verify.status_code == 400
    assert "already been used" in replay_verify.json()["detail"].lower()


def test_password_reset_cannot_reuse_current_password(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="frank@example.test", password="CurrentPassword123")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "frank@example.test"})
    reset_token = req_resp.json()["reset_token"]
    code = delivered[0][1]

    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": code})
    password_reset_token = verify_resp.json()["password_reset_token"]

    # Try setting to identical current password
    same_resp = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": password_reset_token, "new_password": "CurrentPassword123"})
    assert same_resp.status_code == 400
    assert "choose a different password" in same_resp.json()["detail"].lower()


def test_password_reset_password_complexity_validation(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="grace@example.test")

    req_resp = test_client.post("/api/v1/auth/forgot-password", json={"email": "grace@example.test"})
    reset_token = req_resp.json()["reset_token"]
    code = delivered[0][1]

    verify_resp = test_client.post("/api/v1/auth/verify-reset-code", json={"reset_token": reset_token, "code": code})
    token = verify_resp.json()["password_reset_token"]

    # Too short (< 12)
    short = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": token, "new_password": "Short1!"})
    assert short.status_code == 422

    # Missing uppercase
    no_upper = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": token, "new_password": "alllowercase12345"})
    assert no_upper.status_code == 422

    # Missing digit
    no_digit = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": token, "new_password": "NoDigitsInThisPassword"})
    assert no_digit.status_code == 422


def test_password_reset_cooldown_rate_limit(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="heidi@example.test")

    # First request succeeds
    r1 = test_client.post("/api/v1/auth/forgot-password", json={"email": "heidi@example.test"})
    assert r1.status_code == 200

    # Immediate second request fails with 429 cooldown
    r2 = test_client.post("/api/v1/auth/forgot-password", json={"email": "heidi@example.test"})
    assert r2.status_code == 429
    assert "too many verification messages" in r2.json()["detail"].lower()


def test_password_reset_endpoint_aliases(client) -> None:
    test_client, factory, delivered = client
    _create_verified_user(factory, email="ivan@example.test")

    # Alias: /api/v1/auth/request-reset
    r1 = test_client.post("/api/v1/auth/request-reset", json={"email": "ivan@example.test"})
    assert r1.status_code == 200
    reset_token = r1.json()["reset_token"]
    code = delivered[0][1]

    # Alias: /api/v1/auth/verify-reset-otp
    r2 = test_client.post("/api/v1/auth/verify-reset-otp", json={"reset_token": reset_token, "code": code})
    assert r2.status_code == 200
    pr_token = r2.json()["password_reset_token"]

    # Confirm works
    r3 = test_client.post("/api/v1/auth/reset-password", json={"password_reset_token": pr_token, "new_password": "NewPassword123X"})
    assert r3.status_code == 200
