from pathlib import Path
import smtplib
from types import SimpleNamespace

import pytest

from app.config import BACKEND_DIR, Settings
from app.models import User
from app.services import otp
from app.services.otp import configuration_message, deliver, deliver_email_otp, deliver_sms_otp, email_provider_configured, providers_configured, smtp_configuration_status


def _provider_environment(monkeypatch) -> None:
    values = {
        "OTP_PEPPER": "test-only-pepper",
        "EMAIL_PROVIDER": "smtp",
        "SMTP_HOST": "smtp.test.invalid",
        "SMTP_FROM": "no-reply@test.invalid",
        "SMS_PROVIDER": "twilio",
        "SMS_ACCOUNT_SID": "ACtest",
        "SMS_AUTH_TOKEN": "test-only-token",
        "SMS_FROM_NUMBER": "+15550000000",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_configured_otp_secret_and_providers_are_recognized(monkeypatch) -> None:
    _provider_environment(monkeypatch)
    settings = Settings(_env_file=None)

    assert settings.otp_pepper == "test-only-pepper"
    assert providers_configured(settings)
    assert configuration_message(settings) == ""


def test_missing_otp_secret_fails_safely(monkeypatch) -> None:
    _provider_environment(monkeypatch)
    monkeypatch.delenv("OTP_PEPPER")
    settings = Settings(_env_file=None)

    assert settings.otp_pepper is None
    assert not providers_configured(settings)
    assert configuration_message(settings) == "OTP verification is unavailable until OTP_PEPPER is configured."


def test_smtp_readiness_is_independent_from_otp_pepper() -> None:
    settings = Settings(_env_file=None, email_provider="smtp", smtp_host="smtp.example.test", smtp_from="sender@example.test", otp_pepper=None)

    assert email_provider_configured(settings)
    assert smtp_configuration_status(settings).configured


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"smtp_host": None}, "SMTP_HOST is missing"),
        ({"smtp_username": "sender@example.test"}, "SMTP_USERNAME and SMTP_PASSWORD must be provided together"),
        ({"smtp_password": "password"}, "SMTP_USERNAME and SMTP_PASSWORD must be provided together"),
        ({"smtp_from": "not-an-email"}, "SMTP_FROM is invalid"),
        ({"smtp_port": 70000}, "SMTP_PORT must be between 1 and 65535"),
        ({"smtp_use_tls": False}, "SMTP_USE_TLS must be true"),
    ],
)
def test_smtp_configuration_rejects_invalid_required_values(overrides, reason) -> None:
    values = {
        "email_provider": "smtp",
        "smtp_host": "smtp.example.test",
        "smtp_from": "sender@example.test",
        "smtp_port": 587,
        "smtp_username": None,
        "smtp_password": None,
        "smtp_use_tls": True,
    }
    values.update(overrides)
    if values["smtp_port"] == 70000:
        settings = SimpleNamespace(**values)
    else:
        settings = Settings(_env_file=None, **values)

    status = smtp_configuration_status(settings)
    assert not status.configured
    assert status.reason == reason


def test_environment_smtp_values_are_loaded_by_settings(monkeypatch) -> None:
    monkeypatch.setenv("EMAIL_PROVIDER", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "sender@example.test")
    monkeypatch.setenv("SMTP_USE_TLS", "true")
    monkeypatch.setenv("SMTP_TIMEOUT_SECONDS", "12")

    settings = Settings(_env_file=None)

    assert settings.email_provider == "smtp"
    assert settings.smtp_host == "smtp.example.test"
    assert settings.smtp_port == 587
    assert settings.smtp_timeout_seconds == 12
    assert smtp_configuration_status(settings).configured


def test_settings_use_the_backend_env_file_for_diagnostics_and_routes() -> None:
    assert BACKEND_DIR == Path(__file__).resolve().parents[1]
    assert Settings.model_config["env_file"] == BACKEND_DIR / ".env"


def test_console_sms_delivery_is_development_only_and_emits_dedicated_terminal_record(capsys) -> None:
    settings = Settings(app_env="development", otp_pepper="test-pepper", email_provider="smtp", smtp_host="smtp.test.invalid", smtp_from="no-reply@test.invalid", sms_provider="console")
    user = User(id=7, phone_number="+15551234567")

    deliver_sms_otp(user, "123456", settings)

    terminal_output = capsys.readouterr().err
    assert "sentinel.otp.sms.console" in terminal_output
    assert "INFO" in terminal_output
    assert "123456" in terminal_output
    assert "+15551234567" not in terminal_output
    assert "4567" in terminal_output
    assert providers_configured(settings)


def test_console_sms_logger_emits_only_in_development_with_console_provider(capsys) -> None:
    user = User(id=7, phone_number="+15551234567")
    production = Settings(_env_file=None, app_env="production", otp_pepper="test-pepper", sms_provider="console", auth_cookie_secure=True, allowed_origins="https://app.example.test")
    other_provider = Settings(_env_file=None, app_env="development", otp_pepper="test-pepper", sms_provider="twilio")

    with pytest.raises(RuntimeError):
        deliver_sms_otp(user, "123456", production)
    with pytest.raises(RuntimeError):
        deliver_sms_otp(user, "123456", other_provider)

    assert capsys.readouterr().err == ""


def test_console_sms_delivery_is_rejected_in_production() -> None:
    settings = Settings(_env_file=None, app_env="production", otp_pepper="test-pepper", email_provider="smtp", smtp_host="smtp.test.invalid", smtp_from="no-reply@test.invalid", sms_provider="console", auth_cookie_secure=True, allowed_origins="https://app.example.test")

    assert not providers_configured(settings)
    assert "only permitted" in configuration_message(settings)
    with pytest.raises(RuntimeError, match="only permitted"):
        deliver_sms_otp(User(id=7, phone_number="+15551234567"), "123456", settings)


def test_console_sms_provider_requires_the_otp_pepper() -> None:
    settings = Settings(app_env="development", otp_pepper=None, sms_provider="console")

    assert not providers_configured(settings)
    assert "OTP_PEPPER" in configuration_message(settings)


def test_twilio_sms_adapter_submits_message_with_configured_timeout_and_without_secret_logs(monkeypatch, caplog) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

    def fake_post(url, *, data, auth, timeout):
        captured.update(url=url, data=data, auth=auth, timeout=timeout)
        return FakeResponse()

    monkeypatch.setattr(otp.httpx, "post", fake_post)
    settings = Settings(app_env="development", sms_provider="twilio", sms_account_sid="AC-test", sms_auth_token="private-token", sms_from_number="+15550000000", sms_timeout_seconds=7.5, otp_pepper="private-pepper")
    deliver_sms_otp(User(id=17, phone_number="+923001234567"), "583104", settings)

    assert captured == {
        "url": "https://api.twilio.com/2010-04-01/Accounts/AC-test/Messages.json",
        "data": {"From": "+15550000000", "To": "+923001234567", "Body": "Sentinel AI verification code: 583104. Expires in 5 minutes. Do not share this code."},
        "auth": ("AC-test", "private-token"),
        "timeout": 7.5,
    }
    assert "private-token" not in caplog.text
    assert "private-pepper" not in caplog.text
    assert "583104" not in caplog.text


def test_twilio_sms_provider_failure_propagates_for_safe_route_handling(monkeypatch) -> None:
    import httpx

    class FailedResponse:
        def raise_for_status(self) -> None:
            request = httpx.Request("POST", "https://api.twilio.com/2010-04-01/Accounts/AC-test/Messages.json")
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("upstream unavailable", request=request, response=response)

    monkeypatch.setattr(otp.httpx, "post", lambda *_args, **_kwargs: FailedResponse())
    settings = Settings(app_env="development", sms_provider="twilio", sms_account_sid="AC-test", sms_auth_token="private-token", sms_from_number="+15550000000", otp_pepper="private-pepper")
    with pytest.raises(httpx.HTTPStatusError):
        deliver_sms_otp(User(id=18, phone_number="+923001234567"), "583104", settings)


def test_textbee_configuration_is_disabled_by_default_and_requires_key_and_pepper() -> None:
    email = {"email_provider": "smtp", "smtp_host": "smtp.test.invalid", "smtp_from": "sender@example.test"}
    disabled = Settings(_env_file=None, **email, sms_provider="textbee", textbee_api_key="private-key", textbee_enabled=False, otp_pepper="pepper")
    missing_key = Settings(_env_file=None, **email, sms_provider="textbee", textbee_enabled=True, otp_pepper="pepper")
    missing_pepper = Settings(_env_file=None, **email, sms_provider="textbee", textbee_enabled=True, textbee_api_key="private-key")
    configured = Settings(_env_file=None, **email, sms_provider="textbee", textbee_enabled=True, textbee_api_key="private-key", otp_pepper="pepper")

    assert not providers_configured(disabled)
    assert "TEXTBEE_ENABLED=true" in configuration_message(disabled)
    assert not providers_configured(missing_key)
    assert "TEXTBEE_API_KEY" in configuration_message(missing_key)
    assert not providers_configured(missing_pepper)
    assert providers_configured(configured)


def test_textbee_sms_uses_official_request_and_acceptance_response_without_secret_logs(monkeypatch, caplog) -> None:
    captured: dict[str, object] = {}

    class AcceptedResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"data": {"success": True, "smsBatchId": "private-batch-id", "recipientCount": 1}}

    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return AcceptedResponse()

    monkeypatch.setattr(otp.httpx, "post", fake_post)
    settings = Settings(_env_file=None, sms_provider="textbee", textbee_enabled=True, textbee_api_key="private-textbee-key", sms_timeout_seconds=6.5, otp_pepper="private-pepper", otp_ttl_minutes=17)
    with caplog.at_level("INFO", logger="sentinel.otp.delivery"):
        deliver("phone", User(id=19, phone_number="+923001234567"), "583104", settings)

    assert captured == {
        "url": "https://api.textbee.dev/api/v1/gateway/send-sms",
        "headers": {"x-api-key": "private-textbee-key", "Content-Type": "application/json"},
        "json": {"recipients": ["+923001234567"], "message": "Sentinel AI verification code: 583104. Expires in 17 minutes. Do not share this code."},
        "timeout": 6.5,
    }
    assert "583104" not in caplog.text
    assert "private-textbee-key" not in caplog.text
    assert "private-pepper" not in caplog.text
    assert "private-batch-id" not in caplog.text
    assert "OTP submission accepted channel=phone provider=textbee" in caplog.text


def test_textbee_sms_timeout_is_reported_without_revealing_request_data(monkeypatch, caplog) -> None:
    import httpx

    def fail_timeout(*_args, **_kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(otp.httpx, "post", fail_timeout)
    settings = Settings(_env_file=None, sms_provider="textbee", textbee_enabled=True, textbee_api_key="private-textbee-key", otp_pepper="private-pepper")
    with pytest.raises(otp.OtpDeliveryError) as exc_info:
        deliver("phone", User(id=20, phone_number="+923001234567"), "583104", settings)
    otp.log_delivery_failure("phone", settings, exc_info.value)

    assert "private-textbee-key" not in caplog.text
    assert "private-pepper" not in caplog.text
    assert "583104" not in caplog.text
    assert "cause_type=ReadTimeout" in caplog.text


def test_textbee_http_and_malformed_acceptance_failures_are_rejected(monkeypatch) -> None:
    import httpx

    class FailedResponse:
        status_code = 429

        def raise_for_status(self) -> None:
            request = httpx.Request("POST", "https://api.textbee.dev/api/v1/gateway/send-sms")
            response = httpx.Response(429, request=request)
            raise httpx.HTTPStatusError("plan limit", request=request, response=response)

    monkeypatch.setattr(otp.httpx, "post", lambda *_args, **_kwargs: FailedResponse())
    settings = Settings(_env_file=None, sms_provider="textbee", textbee_enabled=True, textbee_api_key="private-textbee-key", otp_pepper="private-pepper")
    with pytest.raises(httpx.HTTPStatusError):
        deliver_sms_otp(User(id=21, phone_number="+923001234567"), "583104", settings)

    class UnacceptedResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"data": {"success": False}}

    monkeypatch.setattr(otp.httpx, "post", lambda *_args, **_kwargs: UnacceptedResponse())
    with pytest.raises(RuntimeError, match="did not confirm acceptance"):
        deliver_sms_otp(User(id=21, phone_number="+923001234567"), "583104", settings)


def test_email_from_name_subject_and_expiry_copy_keep_configured_sender(monkeypatch, caplog) -> None:
    captured: dict[str, object] = {}

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def starttls(self, *, context) -> None:
            assert context is not None
            pass

        def send_message(self, message) -> None:
            captured["message"] = message

    monkeypatch.setattr(otp.smtplib, "SMTP", FakeSMTP)
    settings = Settings(_env_file=None, email_provider="smtp", smtp_host="smtp.example.test", smtp_from="ssabdullah626 <sender@example.test>", otp_pepper="private-pepper", otp_ttl_minutes=13)
    deliver("email", User(id=22, email="recipient@example.test"), "583104", settings)
    message = captured["message"]

    assert message["From"] == "Sentinel AI <sender@example.test>"
    assert message["Subject"] == "Your Sentinel AI Verification Code"
    assert message.get_content() == (
        "Hello,\n\n"
        "Your verification code for Sentinel AI is: 583104\n\n"
        "This code expires in 13 minutes. Do not share it with anyone.\n\n"
        "If you did not request this code, you can ignore this message.\n\n"
        "— Sentinel AI Security Team\n"
    )
    assert "583104" not in caplog.text
    assert "private-pepper" not in caplog.text


def test_gmail_requires_a_complete_authentication_pair() -> None:
    settings = Settings(_env_file=None, app_env="development", otp_pepper="test-pepper", email_provider="smtp", smtp_host="smtp.gmail.com", smtp_from="sender@gmail.test", smtp_username="sender@gmail.test", sms_provider="console")

    assert not providers_configured(settings)
    assert "SMTP_USERNAME and SMTP_PASSWORD" in configuration_message(settings)


def test_gmail_app_password_formatting_is_normalized_without_logging_credentials(monkeypatch) -> None:
    captured: dict[str, str] = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert host == "smtp.gmail.com"
            assert port == 587
            assert timeout == 15.0

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def starttls(self, *, context) -> None:
            assert context is not None
            pass

        def login(self, username: str, password: str) -> None:
            captured["username"] = username
            captured["password"] = password

        def send_message(self, _message) -> None:
            pass

    monkeypatch.setattr(otp.smtplib, "SMTP", FakeSMTP)
    settings = Settings(email_provider="smtp", smtp_host="smtp.gmail.com", smtp_port=587, smtp_username="sender@gmail.test", smtp_password="abcd efgh ijkl mnop", smtp_from="sender@gmail.test", otp_pepper="test-pepper")

    deliver_email_otp(User(id=8, email="recipient@test.invalid"), "123456", settings)

    assert captured == {"username": "sender@gmail.test", "password": "abcdefghijklmnop"}


@pytest.mark.parametrize("failure", [smtplib.SMTPAuthenticationError(535, b"authentication failed"), TimeoutError("timed out")])
def test_smtp_delivery_failures_are_wrapped_without_secret_logs(monkeypatch, caplog, failure) -> None:
    class FailedSMTP:
        def __init__(self, *_args, **_kwargs):
            if isinstance(failure, TimeoutError):
                raise failure

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, *, context):
            raise failure

    monkeypatch.setattr(otp.smtplib, "SMTP", FailedSMTP)
    settings = Settings(_env_file=None, email_provider="smtp", smtp_host="smtp.example.test", smtp_from="sender@example.test", smtp_username="private-user", smtp_password="private-password", otp_pepper="private-pepper")

    with pytest.raises(otp.OtpDeliveryError):
        deliver("email", User(id=23, email="recipient@example.test"), "583104", settings)
    otp.log_delivery_failure("email", settings, otp.OtpDeliveryError("email OTP delivery failed."))

    assert "private-user" not in caplog.text
    assert "private-password" not in caplog.text
    assert "private-pepper" not in caplog.text
    assert "583104" not in caplog.text


def test_successful_smtp_delivery_uses_tls_and_configured_timeout(monkeypatch) -> None:
    captured = {}

    class SuccessfulSMTP:
        def __init__(self, host, port, timeout):
            captured.update(host=host, port=port, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, *, context):
            captured["tls_context"] = context

        def send_message(self, message):
            captured["recipient"] = message["To"]

    monkeypatch.setattr(otp.smtplib, "SMTP", SuccessfulSMTP)
    settings = Settings(_env_file=None, email_provider="smtp", smtp_host="smtp.example.test", smtp_from="sender@example.test", smtp_timeout_seconds=9, otp_pepper="private-pepper")

    deliver_email_otp(User(id=24, email="recipient@example.test"), "583104", settings)

    assert captured["host"] == "smtp.example.test"
    assert captured["port"] == 587
    assert captured["timeout"] == 9
    assert captured["tls_context"] is not None
    assert captured["recipient"] == "recipient@example.test"
