from app.migration_release import _target_is_expected, run
from app.config import Settings
import app.migration_release as migration_release


def test_release_migration_is_disabled_by_default(monkeypatch) -> None:
    settings = Settings(_env_file=None, migration_release_enabled=False)
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)

    assert run() == 0


def test_release_migration_rejects_non_production_target(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        migration_release_enabled=True,
        database_url="mysql+pymysql://user:password@127.0.0.1:3306/sentinel_ai",
    )
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)

    assert run() == 2


def test_release_target_requires_exact_tidb_host_port_and_database() -> None:
    assert _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai")
    assert not _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/other")
    assert not _target_is_expected("mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:3306/sentinel_ai")
