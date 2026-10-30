from pathlib import Path

from app.migration_release import _target_is_expected, run
from app.config import Settings
import app.migration_release as migration_release


def test_release_migration_requires_explicit_production_confirmation(monkeypatch) -> None:
    settings = Settings(_env_file=None)
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)

    assert run() == 2


def test_release_migration_rejects_non_production_target(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        database_url="mysql+pymysql://user:password@127.0.0.1:3306/sentinel_ai",
    )
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)

    assert run(confirm_production_target=True) == 2


def test_release_target_requires_exact_tidb_host_port_and_database() -> None:
    assert _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai")
    assert not _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/other")
    assert not _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:3306/sentinel_ai")


def test_build_configuration_does_not_execute_migrations() -> None:
    root = Path(__file__).parents[1]
    procfile = (root / "Procfile").read_text(encoding="utf-8")
    nixpacks = (root / "nixpacks.toml").read_text(encoding="utf-8")

    assert "migration_release" not in procfile
    assert "release:" not in procfile
    assert "migration_release" not in nixpacks
    assert "uvicorn" in procfile
    assert "uvicorn" in nixpacks
