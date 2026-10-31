import hashlib

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.config import Settings
from app.production_import import EXCLUDED_OPERATIONAL_TABLES, _require_target, _source_engine, _validate_backup
from app.services.diagnostic_access import DiagnosticChallengeManager
from app.services.auth import require_csrf_read_only
from app.models import AuthSession


def test_backup_validation_checks_size_and_optional_checksum(tmp_path) -> None:
    backup = tmp_path / "sentinel.sql"
    backup.write_bytes(b"safe backup contents")
    digest = hashlib.sha256(backup.read_bytes()).hexdigest()

    result = _validate_backup(str(backup), digest)

    assert result["size_bytes"] == len(b"safe backup contents")
    assert result["sha256_verified"] is True
    with pytest.raises(RuntimeError, match="checksum"):
        _validate_backup(str(backup), "0" * 64)


def test_import_target_requires_exact_verified_tidb(monkeypatch) -> None:
    settings = Settings(_env_file=None, database_url="mysql+pymysql://user:password@127.0.0.1:3306/sentinel_ai")
    with pytest.raises(RuntimeError, match="approved TiDB target"):
        _require_target(settings, True)


def test_source_target_cannot_be_tidb(monkeypatch) -> None:
    monkeypatch.setenv("IMPORT_SOURCE_DATABASE_URL", "mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai")
    with pytest.raises(RuntimeError, match="source must not be"):
        _source_engine()


def test_source_url_is_not_required_for_normal_module_import(monkeypatch) -> None:
    monkeypatch.delenv("IMPORT_SOURCE_DATABASE_URL", raising=False)

    import app.production_import as production_import

    assert production_import.IMPORT_TABLES


def test_explicit_source_engine_requires_source_url(monkeypatch) -> None:
    monkeypatch.delenv("IMPORT_SOURCE_DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="IMPORT_SOURCE_DATABASE_URL is required"):
        _source_engine()


def test_diagnostic_challenge_is_single_use_and_replay_protected() -> None:
    manager = DiagnosticChallengeManager()
    challenge = manager.issue("client", "diagnostic-secret", "diagnostic-secret", 60, 5)

    assert challenge is not None
    assert manager.consume("client", challenge, 5) is True
    assert manager.consume("client", challenge, 5) is False
    assert manager.issue("client", "wrong", "diagnostic-secret", 60, 5) is None


def test_diagnostic_challenge_is_rate_limited() -> None:
    manager = DiagnosticChallengeManager()
    for _ in range(5):
        assert manager.issue("client", "wrong", "diagnostic-secret", 60, 5) is None
    assert manager.issue("client", "diagnostic-secret", "diagnostic-secret", 60, 5) is None


def test_read_only_diagnostic_csrf_validation_rejects_missing_header() -> None:
    session = AuthSession(csrf_token_hash=hashlib.sha256(b"csrf-token").hexdigest())
    request = Request({"type": "http", "headers": [(b"cookie", b"sentinel_csrf=csrf-token")], "query_string": b""})
    with pytest.raises(HTTPException) as error:
        require_csrf_read_only(request, session)
    assert error.value.status_code == 403


def test_operational_authentication_tables_are_excluded_by_default() -> None:
    assert set(EXCLUDED_OPERATIONAL_TABLES) == {
        "auth_sessions",
        "otp_challenges",
        "otp_send_attempts",
        "password_reset_challenges",
        "login_attempts",
    }
