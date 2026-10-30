"""Read-only production diagnostics and an explicitly confirmed migration command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import NullPool

from app import models  # noqa: F401
from app.config import get_settings
from app.db import Base
from app.migration_release import EXPECTED_DATABASE, EXPECTED_HEAD, EXPECTED_HOST, _target_is_expected, run as run_migration


def _require_confirmed_target(confirmed: bool):
    settings = get_settings()
    if not confirmed:
        raise RuntimeError("Pass --confirm-production-target from the reviewed production runtime.")
    parsed = urlsplit(settings.database_url)
    if not _target_is_expected(settings.database_url):
        raise RuntimeError("The configured database is not the approved production TiDB target.")
    ca_path = settings.database_ssl_ca_path
    if not ca_path or not Path(ca_path).is_file():
        raise RuntimeError("The configured TiDB CA certificate is missing or unreadable.")
    if not settings.database_connect_args.get("ssl_verify_cert") or not settings.database_connect_args.get("ssl_verify_identity"):
        raise RuntimeError("TiDB certificate and hostname verification are not enabled.")
    return settings, parsed


def _snapshot(connection) -> dict[str, object]:
    inspector = inspect(connection)
    actual_tables = set(inspector.get_table_names())
    required = set(Base.metadata.tables) | {"alembic_version"}
    required_tables = {name: name in actual_tables for name in sorted(required)}
    revisions = list(MigrationContext.configure(connection).get_current_heads()) if "alembic_version" in actual_tables else []
    return {
        "database_host": EXPECTED_HOST,
        "database_port": 4000,
        "database_name": EXPECTED_DATABASE,
        "current_revisions": revisions,
        "expected_head": EXPECTED_HEAD,
        "required_tables": required_tables,
    }


def _schema_snapshot(connection) -> dict[str, object]:
    inspector = inspect(connection)
    result: dict[str, object] = {}
    for name, table in sorted(Base.metadata.tables.items()):
        if not inspector.has_table(name):
            result[name] = {"exists": False, "missing_columns": sorted(column.name for column in table.columns), "missing_indexes": sorted(index.name for index in table.indexes if index.name)}
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(name)}
        actual_indexes = {index["name"] for index in inspector.get_indexes(name) if index.get("name")}
        result[name] = {
            "exists": True,
            "missing_columns": sorted(column.name for column in table.columns if column.name not in actual_columns),
            "missing_indexes": sorted(index.name for index in table.indexes if index.name and index.name not in actual_indexes),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Operate on the verified Sentinel AI production TiDB target.")
    parser.add_argument("command", choices=("diagnose", "verify-schema", "verify", "migrate"))
    parser.add_argument("--confirm-production-target", action="store_true", required=True)
    args = parser.parse_args()
    try:
        settings, _ = _require_confirmed_target(args.confirm_production_target)
        if args.command == "migrate":
            return run_migration(confirm_production_target=True)
        engine = create_engine(settings.database_url, connect_args=settings.database_connect_args, poolclass=NullPool)
        with engine.connect() as connection:
            report = _snapshot(connection)
            if args.command in {"verify-schema", "verify"}:
                report["schema"] = _schema_snapshot(connection)
        if args.command == "verify":
            schema_ok = all(item["exists"] and not item["missing_columns"] and not item["missing_indexes"] for item in report["schema"].values())
            revision_ok = report["current_revisions"] == [EXPECTED_HEAD]
            if not schema_ok or not revision_ok:
                print(json.dumps(report, sort_keys=True))
                return 2
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "unavailable", "error_category": type(exc).__name__}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
