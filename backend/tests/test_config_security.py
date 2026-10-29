import pytest
from pydantic import ValidationError

from app.config import Settings


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
