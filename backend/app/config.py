from functools import lru_cache
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    app_name: str = "Sentinel AI"
    app_env: str = "development"
    database_url: str = "sqlite:///./sentinel.db"
    database_ssl_ca_path: str | None = None
    database_connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    api_v1_prefix: str = "/api/v1"
    allowed_origins: str = "http://localhost:5173,http://localhost:5174,http://localhost:5175"
    trusted_proxy_hosts: str = "127.0.0.1,::1"
    ai_provider: str = "none"
    ai_api_key: str | None = None
    gemini_api_key: str | None = None
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: float = 30.0
    ai_max_input_chars: int = 12000
    ai_max_output_chars: int = 5000
    ai_requests_per_minute: int = 10
    session_ttl_minutes: int = 60
    auth_cookie_name: str = "sentinel_session"
    csrf_cookie_name: str = "sentinel_csrf"
    auth_cookie_secure: bool | None = None
    otp_pepper: str | None = None
    otp_ttl_minutes: int = 5
    otp_max_attempts: int = 5
    otp_resend_cooldown_seconds: int = 60
    otp_max_sends_per_recipient_per_hour: int = 3
    otp_max_sends_per_ip_per_hour: int = 10
    email_provider: str = "none"
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_use_tls: bool = True
    smtp_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    sms_provider: str = "none"
    sms_account_sid: str | None = None
    sms_auth_token: str | None = None
    sms_from_number: str | None = None
    sms_timeout_seconds: float = 10.0
    textbee_enabled: bool = False
    textbee_api_key: str | None = None
    admin_user_ids: str = ""
    admin_diagnostics_enabled: bool = False
    admin_diagnostic_secret: str | None = None
    admin_diagnostic_challenge_ttl_seconds: int = Field(default=60, ge=10, le=300)
    admin_diagnostic_rate_limit: int = Field(default=5, ge=1, le=100)

    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("admin_user_ids")
    @classmethod
    def validate_admin_user_ids(cls, value: str) -> str:
        ids = [item.strip() for item in value.split(",") if item.strip()]
        if any(not item.isascii() or not item.isdecimal() or int(item) < 1 for item in ids):
            raise ValueError("ADMIN_USER_IDS must be a comma-separated list of positive user IDs.")
        return ",".join(dict.fromkeys(ids))

    @field_validator("database_ssl_ca_path")
    @classmethod
    def validate_database_ssl_ca_path(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        certificate_path = Path(value).expanduser()
        try:
            with certificate_path.open("rb"):
                pass
        except OSError as exc:
            raise ValueError("DATABASE_SSL_CA_PATH must point to a readable CA certificate file.") from exc
        return str(certificate_path)

    @property
    def administrator_ids(self) -> frozenset[int]:
        return frozenset(int(item) for item in self.admin_user_ids.split(",") if item)

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        database_host = (urlsplit(self.database_url).hostname or "").lower()
        if database_host.endswith(".tidbcloud.com") and not self.database_ssl_ca_path:
            raise ValueError("DATABASE_SSL_CA_PATH is required for TiDB Cloud connections.")
        if self.admin_diagnostics_enabled and (not self.admin_diagnostic_secret or len(self.admin_diagnostic_secret) < 32):
            raise ValueError("ADMIN_DIAGNOSTIC_SECRET must contain at least 32 characters when diagnostics are enabled.")
        if self.app_env.lower() != "production":
            return self
        if self.auth_cookie_secure is False:
            raise ValueError("AUTH_COOKIE_SECURE must be true in production.")
        if not self.proxy_hosts or "*" in self.proxy_hosts:
            raise ValueError("TRUSTED_PROXY_HOSTS must list explicit trusted proxy addresses in production.")
        try:
            for proxy_host in self.proxy_hosts:
                ipaddress.ip_network(proxy_host, strict=False)
        except ValueError as exc:
            raise ValueError("TRUSTED_PROXY_HOSTS entries must be IP addresses or CIDR ranges.") from exc
        origins = self.cors_origins
        if not origins:
            raise ValueError("ALLOWED_ORIGINS must contain an HTTPS origin in production.")
        for origin in origins:
            parsed = urlsplit(origin)
            hostname = parsed.hostname or ""
            try:
                loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = False
            if parsed.scheme != "https" or not hostname or hostname == "*" or hostname == "localhost" or hostname.endswith(".localhost") or loopback or parsed.path not in {"", "/"}:
                raise ValueError("Production ALLOWED_ORIGINS must contain only HTTPS application origins.")
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def database_connect_args(self) -> dict[str, bool | str | int]:
        if self.database_url.startswith("sqlite"):
            return {"check_same_thread": False}
        connect_args: dict[str, bool | str | int] = {
            "connect_timeout": self.database_connect_timeout_seconds,
            "read_timeout": self.database_connect_timeout_seconds,
            "write_timeout": self.database_connect_timeout_seconds,
        }
        if self.database_ssl_ca_path:
            connect_args.update({
                "ssl_ca": self.database_ssl_ca_path,
                "ssl_verify_cert": True,
                "ssl_verify_identity": True,
            })
        return connect_args

    @property
    def secure_auth_cookies(self) -> bool:
        return self.app_env.lower() == "production" or self.auth_cookie_secure is True

    @property
    def proxy_hosts(self) -> list[str]:
        return [host.strip() for host in self.trusted_proxy_hosts.split(",") if host.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

