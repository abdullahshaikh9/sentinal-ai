from pathlib import Path
from types import SimpleNamespace

import pytest

from app.migration_release import EXPECTED_DATABASE, EXPECTED_HEAD, _target_is_expected, initialize_empty_production, run
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


def _verified_settings(tmp_path, **overrides):
    certificate = tmp_path / "tidb-ca.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    values = {
        "database_url": "mysql+pymysql://user:password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/sentinel_ai",
        "database_ssl_ca_path": str(certificate),
        "database_connect_args": {"ssl_verify_cert": True, "ssl_verify_identity": True},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value

    def scalar_one(self):
        return self.value


class _DiagnosticConnection:
    def __init__(self, statements):
        self.statements = statements

    def execute(self, statement, _params=None):
        sql = str(statement)
        self.statements.append(sql)
        if "GET_LOCK" in sql:
            return _ScalarResult(1)
        if "DATABASE()" in sql:
            return _ScalarResult(EXPECTED_DATABASE)
        return _ScalarResult(None)

    def commit(self):
        self.statements.append("COMMIT")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _DiagnosticEngine:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


def test_empty_verified_schema_is_accepted_and_full_chain_is_requested(monkeypatch, tmp_path):
    settings = _verified_settings(tmp_path)
    statements = []
    connection = _DiagnosticConnection(statements)
    upgrades = []
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)
    monkeypatch.setattr(migration_release, "create_engine", lambda *args, **kwargs: _DiagnosticEngine(connection))
    monkeypatch.setattr(migration_release, "inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: [], get_view_names=lambda: []))
    monkeypatch.setattr(migration_release, "MigrationContext", SimpleNamespace(configure=lambda _connection: SimpleNamespace(get_current_heads=lambda: () if not upgrades else (EXPECTED_HEAD,))))
    monkeypatch.setattr(migration_release.command, "upgrade", lambda _config, revision: upgrades.append(revision))

    assert initialize_empty_production(confirm_production_target=True, initialize_empty=True) == 0
    assert upgrades == [EXPECTED_HEAD]
    assert not any(keyword in statement.upper() for statement in statements for keyword in ("DROP", "TRUNCATE", "DELETE"))


def test_empty_initialization_requires_both_confirmation_flags(monkeypatch, tmp_path):
    settings = _verified_settings(tmp_path)
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)
    monkeypatch.setattr(migration_release, "create_engine", lambda: pytest.fail("connection must not be opened"))

    assert initialize_empty_production(confirm_production_target=True) == 2
    assert initialize_empty_production(initialize_empty=True) == 2


def test_empty_initialization_rejects_wrong_target_and_disabled_tls(monkeypatch, tmp_path):
    wrong_target = _verified_settings(tmp_path, database_url="mysql+pymysql://user:password@127.0.0.1:3306/sentinel_ai")
    monkeypatch.setattr(migration_release, "get_settings", lambda: wrong_target)
    assert initialize_empty_production(confirm_production_target=True, initialize_empty=True) == 2

    tls_disabled = _verified_settings(tmp_path, database_connect_args={"ssl_verify_cert": False, "ssl_verify_identity": False})
    monkeypatch.setattr(migration_release, "get_settings", lambda: tls_disabled)
    assert initialize_empty_production(confirm_production_target=True, initialize_empty=True) == 2


def test_existing_migration_command_still_rejects_empty_schema(monkeypatch, tmp_path):
    settings = _verified_settings(tmp_path)
    connection = _DiagnosticConnection([])
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)
    monkeypatch.setattr(migration_release, "create_engine", lambda *args, **kwargs: _DiagnosticEngine(connection))
    monkeypatch.setattr(migration_release, "MigrationContext", SimpleNamespace(configure=lambda _connection: SimpleNamespace(get_current_heads=lambda: ())))
    monkeypatch.setattr(migration_release.command, "upgrade", lambda *_args: pytest.fail("ordinary migration must not upgrade an empty schema"))

    assert run(confirm_production_target=True) == 2


@pytest.mark.parametrize("objects", [
    {"tables": ["users"], "views": []},
    {"tables": [], "views": ["users_view"]},
])
def test_empty_initialization_rejects_existing_tables_or_views(monkeypatch, objects):
    connection = SimpleNamespace(
        execute=lambda statement: _ScalarResult(EXPECTED_DATABASE),
    )
    monkeypatch.setattr(migration_release, "inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: objects["tables"], get_view_names=lambda: objects["views"]))
    with pytest.raises(RuntimeError, match="existing (tables|views)"):
        migration_release._verify_empty_schema(connection)


def test_empty_initialization_rejects_existing_alembic_revision(monkeypatch):
    connection = SimpleNamespace(execute=lambda statement: _ScalarResult(EXPECTED_DATABASE))
    monkeypatch.setattr(migration_release, "inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: [], get_view_names=lambda: []))
    monkeypatch.setattr(migration_release, "MigrationContext", SimpleNamespace(configure=lambda _connection: SimpleNamespace(get_current_heads=lambda: ("20261028_0009",))))

    with pytest.raises(RuntimeError, match="Alembic revision"):
        migration_release._verify_empty_schema(connection)


def test_migration_failure_is_reported_without_destructive_cleanup(monkeypatch, tmp_path):
    settings = _verified_settings(tmp_path)
    statements = []
    connection = _DiagnosticConnection(statements)
    monkeypatch.setattr(migration_release, "get_settings", lambda: settings)
    monkeypatch.setattr(migration_release, "create_engine", lambda *args, **kwargs: _DiagnosticEngine(connection))
    monkeypatch.setattr(migration_release, "inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: [], get_view_names=lambda: []))
    monkeypatch.setattr(migration_release, "MigrationContext", SimpleNamespace(configure=lambda _connection: SimpleNamespace(get_current_heads=lambda: ())))
    monkeypatch.setattr(migration_release.command, "upgrade", lambda *_args: (_ for _ in ()).throw(RuntimeError("simulated failure")))

    assert initialize_empty_production(confirm_production_target=True, initialize_empty=True) == 2
    assert not any(keyword in statement.upper() for statement in statements for keyword in ("DROP", "TRUNCATE", "DELETE"))


def test_build_configuration_does_not_execute_migrations() -> None:
    root = Path(__file__).parents[1]
    procfile = (root / "Procfile").read_text(encoding="utf-8")
    nixpacks = (root / "nixpacks.toml").read_text(encoding="utf-8")

    assert "migration_release" not in procfile
    assert "release:" not in procfile
    assert "migration_release" not in nixpacks
    assert "uvicorn" in procfile
    assert "uvicorn" in nixpacks
