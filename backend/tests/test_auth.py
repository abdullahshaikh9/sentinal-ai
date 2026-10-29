from datetime import UTC, datetime, timedelta
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import ActivityEvent, AuthSession, Finding, LoginAttempt, OtpChallenge, Scan, User
from app.config import Settings
import app.api.routes as routes
from app.services.auth import hash_password, verify_password
from app.services import otp
from app.services.otp import OtpDeliveryError


def test_login_endpoint_is_registered_at_the_v1_auth_path() -> None:
    operation = app.openapi()["paths"].get("/api/v1/auth/login", {}).get("post")

    assert operation is not None
    assert operation["operationId"] == "login_api_v1_auth_login_post"


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

    delivered: dict[str, str] = {}
    test_settings = Settings(_env_file=None, ai_provider="none", ai_api_key=None, gemini_api_key=None, email_provider="smtp", smtp_host="smtp.test", smtp_from="no-reply@sentinel.test", sms_provider="twilio", sms_account_sid="ACtest", sms_auth_token="test-token", sms_from_number="+15550000000", otp_pepper="test-pepper")
    monkeypatch.setattr(routes, "get_settings", lambda: test_settings)
    monkeypatch.setattr(routes, "deliver", lambda channel, user, code, settings: delivered.__setitem__(channel, code))
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client, factory, delivered
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def _register(client: TestClient, email: str, delivered: dict[str, str]) -> None:
    phone = "+1555" + str(abs(hash(email)) % 10000000).zfill(7)
    response = client.post("/api/v1/auth/register", json={"email": email, "display_name": "Test User", "phone_number": phone, "password": "StrongPassword123"})
    assert response.status_code == 202
    token = response.json()["verification_token"]
    for channel in ("email", "phone"):
        verified = client.post("/api/v1/auth/verify-otp", json={"verification_token": token, "channel": channel, "code": delivered[channel]})
        assert verified.status_code == 200


def test_password_hashing_and_auth_flow(client) -> None:
    test_client, _, delivered = client
    assert hash_password("StrongPassword123") != "StrongPassword123"
    encoded = hash_password("StrongPassword123")
    assert verify_password("StrongPassword123", encoded)
    assert not verify_password("WrongPassword123", encoded)
    _register(test_client, "auth-one@example.test", delivered)
    assert test_client.get("/api/v1/auth/me").status_code == 200
    assert test_client.get("/api/v1/assistant/status").json()["configured"] is False
    assert test_client.post("/api/v1/assistant/query", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]}, json={"question": "Explain my scan"}).status_code == 503
    assert test_client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]}).status_code == 204
    assert test_client.get("/api/v1/auth/me").status_code == 401


def test_invalid_login_and_csrf_are_rejected(client) -> None:
    test_client, _, delivered = client
    _register(test_client, "auth-two@example.test", delivered)
    test_client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]})
    response = test_client.post("/api/v1/auth/login", json={"email": "auth-two@example.test", "password": "wrong-password"})
    assert response.status_code == 401
    test_client.post("/api/v1/auth/login", json={"email": "auth-two@example.test", "password": "StrongPassword123"})
    assert test_client.post("/api/v1/auth/logout").status_code == 403


def test_csrf_is_required_for_asset_and_scan_creation(client) -> None:
    test_client, _, delivered = client
    _register(test_client, "csrf-mutations@example.test", delivered)

    asset = test_client.post("/api/v1/assets", json={"target_url": "https://authorized.example", "authorization_confirmed": True})
    scan = test_client.post("/api/v1/scans", json={"target_url": "https://authorized.example", "authorization_confirmed": True})
    invalid_csrf = test_client.post(
        "/api/v1/assets",
        headers={"X-CSRF-Token": "not-the-session-token"},
        json={"target_url": "https://authorized.example", "authorization_confirmed": True},
    )

    assert asset.status_code == 403
    assert scan.status_code == 403
    assert invalid_csrf.status_code == 403


def test_cross_user_asset_access_is_isolated(client) -> None:
    test_client, _, delivered = client
    _register(test_client, "owner-one@example.test", delivered)
    csrf = test_client.cookies["sentinel_csrf"]
    created = test_client.post("/api/v1/assets", headers={"X-CSRF-Token": csrf}, json={"target_url": "https://owned.example", "authorization_confirmed": True})
    assert created.status_code == 201
    test_client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]})
    _register(test_client, "owner-two@example.test", delivered)
    assert test_client.get("/api/v1/assets").json() == []


def test_expired_session_is_rejected_and_legacy_rows_are_not_exposed(client) -> None:
    test_client, factory, delivered = client
    _register(test_client, "expiry@example.test", delivered)
    db: Session = factory()
    session = db.scalar(select(AuthSession))
    assert session is not None
    session.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    db.close()
    assert test_client.get("/api/v1/auth/me").status_code == 401


def test_cross_user_scan_report_and_verification_access_is_denied(client) -> None:
    test_client, factory, delivered = client
    _register(test_client, "resource-owner@example.test", delivered)
    db: Session = factory()
    user = db.scalar(select(User).where(User.email == "resource-owner@example.test"))
    assert user is not None
    scan = Scan(target_url="https://owned.example", normalized_url="https://owned.example", status="completed", owner_id=user.id)
    db.add(scan)
    db.flush()
    finding = Finding(scan_id=scan.id, title="Observed test finding", severity="low", dedup_key="test-owner-check")
    db.add(finding)
    db.commit()
    scan_id, finding_id = scan.id, finding.id
    db.close()
    test_client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]})
    _register(test_client, "resource-other@example.test", delivered)
    assert test_client.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert test_client.get(f"/api/v1/scans/{scan_id}/report.pdf").status_code == 404
    assert test_client.get(f"/api/v1/scans/{scan_id}/findings.csv").status_code == 404
    assert all(item["id"] != scan_id for item in test_client.get("/api/v1/scans").json()["items"])
    assert test_client.get(f"/api/v1/findings/{finding_id}/verification").status_code == 404
    assert test_client.post(f"/api/v1/findings/{finding_id}/verification", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]}).status_code == 404


def test_login_rate_limit_is_enforced(client) -> None:
    test_client, factory, _ = client
    statuses = [test_client.post("/api/v1/auth/login", json={"email": "rate-limit@example.test", "password": "WrongPassword123"}).status_code for _ in range(6)]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
    with factory() as db:
        attempts = db.query(LoginAttempt).all()
        assert len(attempts) == 15
        assert all(attempt.state == "failed" for attempt in attempts)
        assert all("rate-limit@example.test" not in attempt.attempt_key for attempt in attempts)


def test_registration_requires_real_delivery_and_never_returns_otp(client) -> None:
    test_client, factory, _ = client
    routes.get_settings = lambda: Settings(_env_file=None, otp_pepper="configured-but-no-providers")
    response = test_client.post("/api/v1/auth/register", json={"email": "unconfigured@example.test", "display_name": "Test User", "phone_number": "+15551234567", "password": "StrongPassword123"})
    assert response.status_code == 503
    assert "verification_token" not in response.json()
    with factory() as db:
        assert db.scalar(select(User).where(User.email == "unconfigured@example.test")) is None


def test_duplicate_registration_is_rejected_without_delivery(client, monkeypatch) -> None:
    test_client, _, delivered = client
    _register(test_client, "duplicate@example.test", delivered)
    attempted: list[str] = []
    monkeypatch.setattr(routes, "deliver", lambda channel, _user, _code, _settings: attempted.append(channel))

    response = test_client.post("/api/v1/auth/register", json={"email": "duplicate@example.test", "display_name": "Test User", "phone_number": "+15551234575", "password": "StrongPassword123"})

    assert response.status_code == 409
    assert attempted == []


def test_existing_unverified_login_resumes_mobile_verification_and_authenticates(client, monkeypatch, caplog) -> None:
    test_client, _, delivered = client
    phone = "+15551234568"
    response = test_client.post("/api/v1/auth/register", json={"email": "partial@example.test", "display_name": "Test User", "phone_number": phone, "password": "StrongPassword123"})
    registration_token = response.json()["verification_token"]
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": registration_token, "channel": "email", "code": delivered["email"]}).status_code == 200

    attempted: list[str] = []
    monkeypatch.setattr(routes, "deliver", lambda channel, _user, _code, _settings: attempted.append(channel))
    with caplog.at_level("INFO", logger="sentinel.auth.delivery"):
        login = test_client.post("/api/v1/auth/login", json={"email": "partial@example.test", "password": "StrongPassword123"})
    assert login.status_code == 200
    pending = login.json()
    assert pending["verification_required"] is True
    assert pending["channels"] == ["phone"]
    assert pending["phone_masked"].endswith("4568")
    assert pending["resend_after_seconds"] > 0
    assert attempted == []
    assert "Login OTP challenge reused channel=phone" in caplog.text
    assert "sentinel_session" not in test_client.cookies
    verified = test_client.post("/api/v1/auth/verify-otp", json={"verification_token": pending["verification_token"], "channel": "phone", "code": delivered["phone"]})
    assert verified.status_code == 200
    assert verified.json()["account_verified"] is True
    assert test_client.get("/api/v1/auth/me").status_code == 200


def test_login_sends_fresh_phone_otp_when_existing_challenge_cooldown_elapsed(client, monkeypatch, caplog) -> None:
    test_client, factory, delivered = client
    response = test_client.post("/api/v1/auth/register", json={"email": "cooldown-login@example.test", "display_name": "Test User", "phone_number": "+15551234579", "password": "StrongPassword123"})
    registration_token = response.json()["verification_token"]
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": registration_token, "channel": "email", "code": delivered["email"]}).status_code == 200
    old_phone_code = delivered["phone"]
    with factory() as db:
        challenge = db.scalar(select(OtpChallenge).where(OtpChallenge.channel == "phone"))
        assert challenge is not None
        challenge.last_sent_at = datetime.now(UTC) - timedelta(minutes=2)
        db.commit()
    fresh_code = "000001" if old_phone_code != "000001" else "000002"
    monkeypatch.setattr(otp.secrets, "randbelow", lambda _limit: int(fresh_code))
    attempted: list[str] = []

    def capture_delivery(channel, _user, code, _settings):
        attempted.append(channel)
        delivered[channel] = code

    monkeypatch.setattr(routes, "deliver", capture_delivery)
    with caplog.at_level("INFO", logger="sentinel.auth.delivery"):
        login = test_client.post("/api/v1/auth/login", json={"email": "cooldown-login@example.test", "password": "StrongPassword123"})

    assert login.status_code == 200
    assert login.json()["channels"] == ["phone"]
    assert attempted == ["phone"]
    assert delivered["phone"] != old_phone_code
    assert login.json()["resend_after_seconds"] == routes.get_settings().otp_resend_cooldown_seconds
    assert "reason=resend_cooldown_elapsed action=create_and_deliver" in caplog.text
    assert delivered["phone"] not in caplog.text
    assert "OTP_PEPPER" not in caplog.text


def test_login_for_unverified_account_without_a_prior_challenge_delivers_required_codes(client) -> None:
    test_client, factory, delivered = client
    with factory() as db:
        db.add(User(email="legacy-unverified@example.test", display_name="Legacy User", phone_number="+15551234577", password_hash=hash_password("StrongPassword123")))
        db.commit()

    response = test_client.post("/api/v1/auth/login", json={"email": "legacy-unverified@example.test", "password": "StrongPassword123"})

    assert response.status_code == 200
    pending = response.json()
    assert pending["channels"] == ["email", "phone"]
    assert pending["phone_masked"].endswith("4577")
    assert set(delivered) == {"email", "phone"}
    assert all(code not in response.text for code in delivered.values())
    assert "sentinel_session" not in test_client.cookies
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": pending["verification_token"], "channel": "email", "code": delivered["email"]}).status_code == 200
    phone_result = test_client.post("/api/v1/auth/verify-otp", json={"verification_token": pending["verification_token"], "channel": "phone", "code": delivered["phone"]})
    assert phone_result.status_code == 200
    assert phone_result.json()["account_verified"] is True
    assert test_client.get("/api/v1/auth/me").status_code == 200


def test_login_for_already_verified_account_authenticates_without_otp(client) -> None:
    test_client, _, delivered = client
    _register(test_client, "verified-login@example.test", delivered)
    test_client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": test_client.cookies["sentinel_csrf"]})

    response = test_client.post("/api/v1/auth/login", json={"email": "verified-login@example.test", "password": "StrongPassword123"})

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "verified-login@example.test"
    assert "verification_token" not in response.json()


def test_password_change_keeps_current_session_and_records_security_event(client) -> None:
    test_client, factory, delivered = client
    _register(test_client, "password-change@example.test", delivered)
    with factory() as db:
        user = db.query(User).filter_by(email="password-change@example.test").one()
        current_session = db.query(AuthSession).filter_by(user_id=user.id, revoked_at=None).one()
        old_hash = user.password_hash
    app.dependency_overrides[routes.require_csrf] = lambda: current_session

    wrong = test_client.post("/api/v1/auth/change-password", json={"current_password": "WrongPassword123", "new_password": "NewStrongPassword123"})
    assert wrong.status_code == 400
    changed = test_client.post("/api/v1/auth/change-password", json={"current_password": "StrongPassword123", "new_password": "NewStrongPassword123"})
    assert changed.status_code == 200
    assert "other active sessions were signed out" in changed.json()["message"].lower()
    assert test_client.get("/api/v1/auth/me").status_code == 200
    with factory() as db:
        user = db.query(User).filter_by(email="password-change@example.test").one()
        assert user.password_hash != old_hash
        assert verify_password("NewStrongPassword123", user.password_hash)
        assert db.query(ActivityEvent).filter_by(owner_id=user.id, event_type="auth.password_changed").count() == 1
def test_invalid_otp_is_limited_and_valid_code_cannot_bypass_attempts(client) -> None:
    test_client, _, delivered = client
    response = test_client.post("/api/v1/auth/register", json={"email": "otp-attempts@example.test", "display_name": "Test User", "phone_number": "+15551234569", "password": "StrongPassword123"})
    token = response.json()["verification_token"]

    statuses = [test_client.post("/api/v1/auth/verify-otp", json={"verification_token": token, "channel": "email", "code": "000000"}).status_code for _ in range(5)]
    assert statuses == [400] * 5
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": token, "channel": "email", "code": delivered["email"]}).status_code == 400


def test_phone_otp_rejects_incorrect_and_expired_codes(client) -> None:
    test_client, factory, delivered = client
    response = test_client.post("/api/v1/auth/register", json={"email": "phone-expired@example.test", "display_name": "Test User", "phone_number": "+15551234576", "password": "StrongPassword123"})
    token = response.json()["verification_token"]
    body = {"verification_token": token, "channel": "phone", "code": "000000"}
    assert test_client.post("/api/v1/auth/verify-otp", json=body).status_code == 400
    with factory() as db:
        challenge = db.scalar(select(OtpChallenge).where(OtpChallenge.channel == "phone"))
        assert challenge is not None
        challenge.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert test_client.post("/api/v1/auth/verify-otp", json={**body, "code": delivered["phone"]}).status_code == 400


def test_expired_otp_and_resend_cooldown_are_rejected(client) -> None:
    test_client, factory, delivered = client
    response = test_client.post("/api/v1/auth/register", json={"email": "otp-expiry@example.test", "display_name": "Test User", "phone_number": "+15551234570", "password": "StrongPassword123"})
    token = response.json()["verification_token"]
    with factory() as db:
        challenge = db.scalar(select(OtpChallenge).where(OtpChallenge.channel == "email"))
        assert challenge is not None
        challenge.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": token, "channel": "email", "code": delivered["email"]}).status_code == 400
    assert test_client.post("/api/v1/auth/resend-otp", json={"verification_token": token, "channel": "phone"}).status_code == 429


def test_phone_otp_can_be_resent_after_cooldown(client) -> None:
    test_client, factory, delivered = client
    response = test_client.post("/api/v1/auth/register", json={"email": "phone-resend@example.test", "display_name": "Test User", "phone_number": "+15551234578", "password": "StrongPassword123"})
    token = response.json()["verification_token"]
    previous_code = delivered["phone"]
    with factory() as db:
        challenge = db.scalar(select(OtpChallenge).where(OtpChallenge.channel == "phone"))
        assert challenge is not None
        challenge.last_sent_at = datetime.now(UTC) - timedelta(minutes=2)
        db.commit()

    resent = test_client.post("/api/v1/auth/resend-otp", json={"verification_token": token, "channel": "phone"})

    assert resent.status_code == 202
    assert resent.json()["resend_after_seconds"] == routes.get_settings().otp_resend_cooldown_seconds
    assert delivered["phone"] != previous_code
    assert test_client.post("/api/v1/auth/verify-otp", json={"verification_token": token, "channel": "phone", "code": delivered["phone"]}).status_code == 200


def test_registration_attempts_both_channels_when_email_delivery_fails(client, monkeypatch) -> None:
    test_client, _, _ = client
    attempted: list[str] = []

    def fail_email_then_deliver_phone(channel, _user, _code, _settings):
        attempted.append(channel)
        if channel == "email":
            raise OtpDeliveryError("safe test failure")

    monkeypatch.setattr(routes, "deliver", fail_email_then_deliver_phone)
    response = test_client.post("/api/v1/auth/register", json={"email": "delivery-failure@example.test", "display_name": "Test User", "phone_number": "+15551234571", "password": "StrongPassword123"})

    assert response.status_code == 503
    assert attempted == ["email", "phone"]
    assert "verification_token" not in response.json()


@pytest.mark.parametrize("failed_channel", ["email", "phone"])
def test_registration_delivers_other_channel_when_provider_raises_unexpected_error(client, monkeypatch, caplog, failed_channel) -> None:
    test_client, _, delivered = client
    attempted: list[str] = []

    def fail_one_channel(channel, _user, code, _settings):
        attempted.append(channel)
        if channel == failed_channel:
            raise ValueError("private provider detail")
        delivered[channel] = code

    monkeypatch.setattr(routes, "deliver", fail_one_channel)
    with caplog.at_level("ERROR", logger="sentinel.otp.delivery"):
        response = test_client.post("/api/v1/auth/register", json={"email": f"{failed_channel}-failure@example.test", "display_name": "Test User", "phone_number": "+15551234572", "password": "StrongPassword123"})

    assert response.status_code == 503
    assert attempted == ["email", "phone"]
    assert "private provider detail" not in caplog.text
    assert "ValueError" in caplog.text
    assert "test-token" not in caplog.text
    assert "test-pepper" not in caplog.text
    assert "verification_token" not in response.json()


def test_registration_flow_invokes_both_deliveries_and_returns_no_codes(client, monkeypatch) -> None:
    test_client, factory, _ = client
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(routes, "deliver", lambda channel, _user, code, _settings: sent.append((channel, code)))

    response = test_client.post("/api/v1/auth/register", json={"email": "full-flow@example.test", "display_name": "Test User", "phone_number": "+15551234573", "password": "StrongPassword123"})

    assert response.status_code == 202
    assert [channel for channel, _ in sent] == ["email", "phone"]
    assert all(len(code) == 6 and code.isdigit() for _, code in sent)
    assert all(code not in response.text for _, code in sent)
    assert "test-token" not in response.text
    assert "test-pepper" not in response.text
    assert "verification_token" in response.json()
    with factory() as db:
        challenges = db.scalars(select(OtpChallenge).where(OtpChallenge.registration_token_hash.is_not(None))).all()
        assert {challenge.channel for challenge in challenges} == {"email", "phone"}


def test_textbee_registration_acceptance_keeps_code_and_key_out_of_response(client, monkeypatch, caplog) -> None:
    import re

    test_client, _, _ = client
    settings = Settings(
        _env_file=None,
        email_provider="smtp",
        smtp_host="smtp.test.invalid",
        smtp_from="sender@example.test",
        sms_provider="textbee",
        textbee_enabled=True,
        textbee_api_key="private-textbee-key",
        otp_pepper="private-pepper",
    )
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    monkeypatch.setattr(otp, "deliver_email_otp", lambda *_args: None)
    sms_request: dict[str, object] = {}

    class AcceptedResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self):
            return {"data": {"success": True, "smsBatchId": "private-batch-id", "recipientCount": 1}}

    def fake_post(_url, **kwargs):
        sms_request.update(kwargs)
        return AcceptedResponse()

    monkeypatch.setattr(otp.httpx, "post", fake_post)
    monkeypatch.setattr(routes, "deliver", lambda channel, user, code, provider_settings: otp.deliver(channel, user, code, provider_settings))
    with caplog.at_level("INFO", logger="sentinel.otp.delivery"):
        response = test_client.post("/api/v1/auth/register", json={"email": "textbee-success@example.test", "display_name": "Test User", "phone_number": "+15551234581", "password": "StrongPassword123"})

    message = sms_request["json"]["message"]
    code = re.search(r"verification code: (\d{6})", message).group(1)
    assert response.status_code == 202
    assert "private-textbee-key" not in response.text
    assert "private-batch-id" not in response.text
    assert code not in response.text
    assert code not in caplog.text
    assert "OTP submission accepted channel=phone provider=textbee" in caplog.text


def test_textbee_registration_failure_is_reported_without_provider_details_or_otp(client, monkeypatch, caplog) -> None:
    import httpx
    import re

    test_client, _, _ = client
    settings = Settings(
        _env_file=None,
        email_provider="smtp",
        smtp_host="smtp.test.invalid",
        smtp_from="sender@example.test",
        sms_provider="textbee",
        textbee_enabled=True,
        textbee_api_key="private-textbee-key",
        otp_pepper="private-pepper",
    )
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    monkeypatch.setattr(otp, "deliver_email_otp", lambda *_args: None)
    monkeypatch.setattr(routes, "deliver", lambda channel, user, code, provider_settings: otp.deliver(channel, user, code, provider_settings))
    submitted_message: list[str] = []

    class RejectedResponse:
        status_code = 429

        def raise_for_status(self) -> None:
            request = httpx.Request("POST", "https://api.textbee.dev/api/v1/gateway/send-sms")
            response = httpx.Response(429, request=request)
            raise httpx.HTTPStatusError("private provider response", request=request, response=response)

    def fake_post(_url, **kwargs):
        submitted_message.append(kwargs["json"]["message"])
        return RejectedResponse()

    monkeypatch.setattr(otp.httpx, "post", fake_post)
    with caplog.at_level("ERROR", logger="sentinel.otp.delivery"):
        response = test_client.post("/api/v1/auth/register", json={"email": "textbee-failure@example.test", "display_name": "Test User", "phone_number": "+15551234582", "password": "StrongPassword123"})

    code = re.search(r"verification code: (\d{6})", submitted_message[0]).group(1)
    assert response.status_code == 503
    assert "verification_token" not in response.json()
    assert "private-textbee-key" not in response.text + caplog.text
    assert "private-pepper" not in response.text + caplog.text
    assert "private provider response" not in caplog.text
    assert "status_code=429" in caplog.text
    assert code not in response.text + caplog.text


def test_registration_calls_console_sms_provider_and_records_safe_delivery_lifecycle(client, monkeypatch, caplog) -> None:
    test_client, _, _ = client
    settings = Settings(_env_file=None, app_env="development", otp_pepper="test-pepper", email_provider="smtp", smtp_host="smtp.test.invalid", smtp_from="no-reply@test.invalid", sms_provider="console")
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    email_deliveries: list[str] = []
    monkeypatch.setattr(otp, "deliver_email_otp", lambda _user, code, _settings: email_deliveries.append(code))
    monkeypatch.setattr(routes, "deliver", lambda channel, user, code, provider_settings: otp.deliver(channel, user, code, provider_settings))
    sms_logger = otp.console_sms_logger
    captured_records: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured_records.append(record)

    capture_handler = CaptureHandler()
    sms_logger.addHandler(capture_handler)
    try:
        with caplog.at_level("INFO", logger="sentinel.otp.delivery"):
            response = test_client.post("/api/v1/auth/register", json={"email": "console-flow@example.test", "display_name": "Test User", "phone_number": "+15551234574", "password": "StrongPassword123"})
    finally:
        sms_logger.removeHandler(capture_handler)

    assert response.status_code == 202
    assert len(email_deliveries) == 1
    assert len(captured_records) == 1
    record = captured_records[0]
    assert record.name == "sentinel.otp.sms.console"
    assert record.levelno == logging.INFO
    assert "Development mobile OTP generated" in record.getMessage()
    assert "channel=phone provider=console" in caplog.text
    assert "OTP delivery started channel=phone provider=console" in caplog.text
    assert "OTP submission accepted channel=phone provider=console" in caplog.text
    assert email_deliveries[0] not in record.getMessage()
    assert "test-pepper" not in caplog.text

