import pytest
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app import db


def test_production_requires_secure_cookies_and_https_origins() -> None:
    with pytest.raises(ValidationError, match="AUTH_COOKIE_SECURE must be true"):
        Settings(_env_file=None, app_env="production", auth_cookie_secure=False, allowed_origins="https://app.example.test")
    with pytest.raises(ValidationError, match="HTTPS application origins"):
        Settings(_env_file=None, app_env="production", auth_cookie_secure=True, allowed_origins="http://localhost:5175")

    settings = Settings(_env_file=None, app_env="production", auth_cookie_secure=True, allowed_origins="https://app.example.test")
    assert settings.secure_auth_cookies is True


def test_production_rejects_wildcard_trusted_proxy_configuration() -> None:
    with pytest.raises(ValidationError, match="TRUSTED_PROXY_HOSTS"):
        Settings(_env_file=None, app_env="production", allowed_origins="https://app.example.test", trusted_proxy_hosts="*")

    settings = Settings(_env_file=None, app_env="production", allowed_origins="https://app.example.test", trusted_proxy_hosts="10.20.0.0/16,::1")
    assert settings.proxy_hosts == ["10.20.0.0/16", "::1"]


def test_production_https_and_hsts_only_trust_configured_proxy() -> None:
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    from app.main import _HSTSMiddleware

    def create_test_app(trusted_hosts: str) -> FastAPI:
        app = FastAPI()
        app.get("/health")(lambda: {"status": "ok"})

        def client_ip(request: Request):
            return {"ip": request.client.host}

        app.get("/client-ip")(client_ip)
        app.add_middleware(HTTPSRedirectMiddleware)
        app.add_middleware(_HSTSMiddleware)
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=trusted_hosts)
        return app

    with TestClient(create_test_app("127.0.0.1"), base_url="http://app.example.test") as untrusted_client:
        untrusted = untrusted_client.get("/health", headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
        assert untrusted.status_code == 307
        assert untrusted.headers["location"].startswith("https://app.example.test/")
        assert "strict-transport-security" not in untrusted.headers

    with TestClient(create_test_app("127.0.0.1"), base_url="https://app.example.test") as untrusted_client:
        untrusted_ip = untrusted_client.get("/client-ip", headers={"X-Forwarded-For": "198.51.100.77"})
        assert untrusted_ip.json()["ip"] == "testclient"

    with TestClient(create_test_app("testclient"), base_url="http://app.example.test") as trusted_client:
        trusted = trusted_client.get("/health", headers={"X-Forwarded-Proto": "https"})
        assert trusted.status_code == 200
        assert trusted.headers["strict-transport-security"] == "max-age=31536000"
        trusted_ip = trusted_client.get("/client-ip", headers={"X-Forwarded-For": "198.51.100.77"})
        assert trusted_ip.json()["ip"] == "198.51.100.77"


def test_development_can_use_http_and_insecure_local_cookie() -> None:
    settings = Settings(_env_file=None, app_env="development", auth_cookie_secure=False, allowed_origins="http://localhost:5175")
    assert settings.secure_auth_cookies is False


def test_administrator_allowlist_accepts_positive_ids_and_rejects_invalid_values() -> None:
    settings = Settings(_env_file=None, admin_user_ids="12, 34,12")
    assert settings.administrator_ids == frozenset({12, 34})
    with pytest.raises(ValidationError, match="ADMIN_USER_IDS"):
        Settings(_env_file=None, admin_user_ids="12,0,not-an-id")


def test_tidb_tls_connect_args_are_verified_and_passed_to_the_engine(tmp_path, monkeypatch) -> None:
    certificate = tmp_path / "tidb-ca.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        database_url="mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai",
        database_ssl_ca_path=str(certificate),
    )
    captured: dict[str, object] = {}

    def fake_create_engine(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(db, "create_engine", fake_create_engine)
    db.create_database_engine(settings)

    assert captured["connect_args"] == {
        "connect_timeout": 10,
        "read_timeout": 10,
        "write_timeout": 10,
        "ssl_ca": str(certificate),
        "ssl_verify_cert": True,
        "ssl_verify_identity": True,
    }


def test_tidb_requires_a_readable_ca_certificate(tmp_path) -> None:
    url = "mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai"
    with pytest.raises(ValidationError, match="DATABASE_SSL_CA_PATH is required"):
        Settings(_env_file=None, database_url=url)
    with pytest.raises(ValidationError, match="readable CA certificate"):
        Settings(_env_file=None, database_url=url, database_ssl_ca_path=str(tmp_path / "missing.pem"))


def test_local_mysql_configuration_remains_unchanged() -> None:
    settings = Settings(_env_file=None, database_url="mysql+pymysql://user:password@127.0.0.1:3306/sentinel_ai")
    assert settings.database_connect_args == {"connect_timeout": 10, "read_timeout": 10, "write_timeout": 10}


def test_ethiodeploy_mysql_without_custom_ca_keeps_connection_configuration_optional() -> None:
    settings = Settings(
        _env_file=None,
        database_url="mysql+pymysql://user:password@mysql-addon.internal:3306/ethiodeploy",
    )

    assert settings.database_connect_args == {
        "connect_timeout": 10,
        "read_timeout": 10,
        "write_timeout": 10,
    }


def test_ethiodeploy_mysql_custom_ca_is_passed_with_verification(tmp_path) -> None:
    certificate = tmp_path / "ethiodeploy-ca.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        database_url="mysql+pymysql://user:password@mysql-addon.internal:3306/ethiodeploy",
        database_ssl_ca_path=str(certificate),
    )

    assert settings.database_connect_args["ssl_ca"] == str(certificate)
    assert settings.database_connect_args["ssl_verify_cert"] is True
    assert settings.database_connect_args["ssl_verify_identity"] is True


def test_ethiodeploy_mysql_missing_or_invalid_ca_is_rejected(tmp_path) -> None:
    url = "mysql+pymysql://user:password@mysql-addon.internal:3306/ethiodeploy"
    with pytest.raises(ValidationError, match="readable CA certificate"):
        Settings(_env_file=None, database_url=url, database_ssl_ca_path=str(tmp_path / "missing.pem"))

    invalid_path = tmp_path / "directory"
    invalid_path.mkdir()
    with pytest.raises(ValidationError, match="readable CA certificate"):
        Settings(_env_file=None, database_url=url, database_ssl_ca_path=str(invalid_path))


def test_database_connection_failure_is_sanitized() -> None:
    error = OperationalError("connect", {}, OSError("certificate details and password must not escape"))

    assert db.database_error_category(error) == "tls_error"


def test_diagnostic_feature_requires_a_high_entropy_secret() -> None:
    with pytest.raises(ValidationError, match="ADMIN_DIAGNOSTIC_SECRET"):
        Settings(_env_file=None, admin_diagnostics_enabled=True, admin_diagnostic_secret="too-short")
    settings = Settings(_env_file=None, admin_diagnostics_enabled=True, admin_diagnostic_secret="diagnostic-secret-for-tests-32-chars")
    assert settings.admin_diagnostics_enabled is True
