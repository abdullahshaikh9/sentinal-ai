"""Dry-run-first, conflict-detecting import of local Sentinel data into TiDB."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from app import models  # noqa: F401
from app.config import Settings
from app.db import Base
from app.migration_release import EXPECTED_DATABASE, EXPECTED_HEAD, EXPECTED_HOST, _target_is_expected
from app.production_db_ops import REQUIRED_TABLE_NAMES, _schema_issues, collect_diagnostic_report


IMPORT_TABLES = (
    "users",
    "assets",
    "scans",
    "findings",
    "verification_attempts",
    "report_metadata",
    "activity_events",
    "finding_remediation",
    "remediation_changes",
    "notifications",
)
EXCLUDED_OPERATIONAL_TABLES = (
    "auth_sessions",
    "otp_challenges",
    "otp_send_attempts",
    "password_reset_challenges",
    "login_attempts",
)
SYSTEM_TABLES = ("alembic_version", "login_rate_limit_mutex")


def _validate_backup(path: str, expected_sha256: str | None) -> dict[str, object]:
    backup = Path(path).expanduser()
    if not backup.is_file() or backup.stat().st_size == 0:
        raise RuntimeError("The source backup is missing or empty.")
    digest = hashlib.sha256()
    with backup.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if expected_sha256 and actual.lower() != expected_sha256.lower():
        raise RuntimeError("The source backup checksum does not match the supplied checksum.")
    return {"path": str(backup), "size_bytes": backup.stat().st_size, "sha256_verified": bool(expected_sha256)}


def _require_target(settings: Settings, confirmed: bool) -> None:
    if not confirmed:
        raise RuntimeError("Production target confirmation is required.")
    if not _target_is_expected(settings.database_url):
        raise RuntimeError("The configured destination is not the approved TiDB target.")
    args = settings.database_connect_args
    if not settings.database_ssl_ca_path or args.get("ssl_verify_cert") is not True or args.get("ssl_verify_identity") is not True:
        raise RuntimeError("TiDB CA, certificate verification, and hostname verification are required.")


def _source_engine() -> object:
    source_url = os.environ.get("IMPORT_SOURCE_DATABASE_URL")
    if not source_url:
        raise RuntimeError("IMPORT_SOURCE_DATABASE_URL is required; no source credential was read from output.")
    parsed = urlsplit(source_url)
    if parsed.hostname == EXPECTED_HOST or parsed.port == 4000:
        raise RuntimeError("The source must not be the production TiDB target.")
    return create_engine(source_url, poolclass=NullPool)


def _table_counts(connection, table_names: tuple[str, ...]) -> dict[str, int]:
    actual = set(inspect(connection).get_table_names())
    counts: dict[str, int] = {}
    for name in table_names:
        if name in actual:
            counts[name] = int(connection.execute(text(f"SELECT COUNT(*) FROM `{name}`")).scalar_one())
    return counts


def _source_relationship_issues(connection) -> list[str]:
    checks = (
        ("assets.owner_id->users", "SELECT COUNT(*) FROM assets a LEFT JOIN users u ON u.id=a.owner_id WHERE a.owner_id IS NOT NULL AND u.id IS NULL"),
        ("scans.owner_id->users", "SELECT COUNT(*) FROM scans s LEFT JOIN users u ON u.id=s.owner_id WHERE s.owner_id IS NOT NULL AND u.id IS NULL"),
        ("scans.asset_id->assets", "SELECT COUNT(*) FROM scans s LEFT JOIN assets a ON a.id=s.asset_id WHERE s.asset_id IS NOT NULL AND a.id IS NULL"),
        ("findings.scan_id->scans", "SELECT COUNT(*) FROM findings f LEFT JOIN scans s ON s.id=f.scan_id WHERE s.id IS NULL"),
        ("verification.scan_id->scans", "SELECT COUNT(*) FROM verification_attempts v LEFT JOIN scans s ON s.id=v.scan_id WHERE s.id IS NULL"),
        ("verification.finding_id->findings", "SELECT COUNT(*) FROM verification_attempts v LEFT JOIN findings f ON f.id=v.finding_id WHERE v.finding_id IS NOT NULL AND f.id IS NULL"),
        ("reports.scan_id->scans", "SELECT COUNT(*) FROM report_metadata r LEFT JOIN scans s ON s.id=r.scan_id WHERE s.id IS NULL"),
        ("activity.owner_id->users", "SELECT COUNT(*) FROM activity_events e LEFT JOIN users u ON u.id=e.owner_id WHERE e.owner_id IS NOT NULL AND u.id IS NULL"),
        ("activity.scan_id->scans", "SELECT COUNT(*) FROM activity_events e LEFT JOIN scans s ON s.id=e.scan_id WHERE e.scan_id IS NOT NULL AND s.id IS NULL"),
        ("activity.finding_id->findings", "SELECT COUNT(*) FROM activity_events e LEFT JOIN findings f ON f.id=e.finding_id WHERE e.finding_id IS NOT NULL AND f.id IS NULL"),
        ("sessions.user_id->users", "SELECT COUNT(*) FROM auth_sessions a LEFT JOIN users u ON u.id=a.user_id WHERE u.id IS NULL"),
        ("notifications.user_id->users", "SELECT COUNT(*) FROM notifications n LEFT JOIN users u ON u.id=n.user_id WHERE u.id IS NULL"),
        ("notifications.scan_id->scans", "SELECT COUNT(*) FROM notifications n LEFT JOIN scans s ON s.id=n.scan_id WHERE n.scan_id IS NOT NULL AND s.id IS NULL"),
        ("notifications.finding_id->findings", "SELECT COUNT(*) FROM notifications n LEFT JOIN findings f ON f.id=n.finding_id WHERE n.finding_id IS NOT NULL AND f.id IS NULL"),
        ("finding_remediation.finding_id->findings", "SELECT COUNT(*) FROM finding_remediation r LEFT JOIN findings f ON f.id=r.finding_id WHERE f.id IS NULL"),
        ("remediation_changes.finding_id->findings", "SELECT COUNT(*) FROM remediation_changes r LEFT JOIN findings f ON f.id=r.finding_id WHERE f.id IS NULL"),
    )
    return [name for name, query in checks if int(connection.execute(text(query)).scalar_one())]


def build_plan(source_connection, destination_connection, settings: Settings, backup: dict[str, object]) -> dict[str, object]:
    source_counts = _table_counts(source_connection, IMPORT_TABLES + EXCLUDED_OPERATIONAL_TABLES)
    source_tables = set(inspect(source_connection).get_table_names())
    source_revisions = list(source_connection.execute(text("SELECT version_num FROM alembic_version")).scalars()) if "alembic_version" in source_tables else []
    source_schema_issues = _schema_issues(source_connection)
    destination_counts = _table_counts(destination_connection, REQUIRED_TABLE_NAMES)
    destination_report = collect_diagnostic_report(destination_connection, settings)
    conflicts = [name for name in IMPORT_TABLES + EXCLUDED_OPERATIONAL_TABLES if destination_counts.get(name, 0)]
    mutex_count = destination_counts.get("login_rate_limit_mutex", 0)
    if mutex_count not in {0, 1}:
        conflicts.append("login_rate_limit_mutex")
    source_missing = [name for name in IMPORT_TABLES if name not in source_counts]
    relationship_issues = _source_relationship_issues(source_connection)
    safe = bool(
        destination_report["current_revisions"] == [EXPECTED_HEAD]
        and destination_report["schema_compatible"]
        and source_revisions == [EXPECTED_HEAD]
        and not source_schema_issues
        and not conflicts
        and not source_missing
        and not relationship_issues
    )
    return {
        "status": "safe_to_import" if safe else "blocked",
        "backup": backup,
        "destination_identity": destination_report["database_identity"],
        "destination_revision": destination_report["current_revisions"],
        "destination_counts": destination_counts,
        "source_counts": source_counts,
        "source_revision": source_revisions,
        "source_schema_issues": source_schema_issues,
        "import_tables": list(IMPORT_TABLES),
        "excluded_operational_tables": {name: "Excluded by default because records contain sessions, OTPs, reset challenges, or temporary login state." for name in EXCLUDED_OPERATIONAL_TABLES},
        "destination_conflicts": conflicts,
        "source_missing_tables": source_missing,
        "source_relationship_issues": relationship_issues,
        "schema_issues": destination_report["schema_issues"],
    }


def _copy_table(source_connection, destination_connection, table_name: str, batch_size: int) -> int:
    table = Base.metadata.tables[table_name]
    primary_key = next(iter(table.primary_key.columns))
    total = 0
    offset = 0
    while True:
        rows = source_connection.execute(select(table).order_by(primary_key).limit(batch_size).offset(offset)).mappings().all()
        if not rows:
            return total
        destination_connection.execute(table.insert(), [dict(row) for row in rows])
        total += len(rows)
        offset += len(rows)


def execute_import(source_engine, destination_engine, settings: Settings, backup: dict[str, object], batch_size: int) -> dict[str, object]:
    with source_engine.connect() as source_connection, destination_engine.connect() as destination_connection:
        lock = destination_connection.execute(text("SELECT GET_LOCK(:lock_name, 1)"), {"lock_name": "sentinel_ai_data_import"}).scalar()
        if lock != 1:
            raise RuntimeError("Import refused because another controlled operation is active.")
        try:
            destination_connection.commit()
            with destination_connection.begin():
                plan = build_plan(source_connection, destination_connection, settings, backup)
                if plan["status"] != "safe_to_import":
                    raise RuntimeError("Import refused because the destination or source is not in the reviewed safe state.")
                copied = {name: _copy_table(source_connection, destination_connection, name, batch_size) for name in IMPORT_TABLES}
            return {"status": "imported", "copied_counts": copied}
        finally:
            destination_connection.execute(text("SELECT RELEASE_LOCK(:lock_name)"), {"lock_name": "sentinel_ai_data_import"})
            destination_connection.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan or execute a protected Sentinel AI local-to-TiDB import.")
    parser.add_argument("command", choices=("plan", "import"))
    parser.add_argument("--backup-path", required=True)
    parser.add_argument("--backup-sha256")
    parser.add_argument("--confirm-production-target", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-import", action="store_true")
    parser.add_argument("--batch-size", type=int, default=250)
    args = parser.parse_args()
    try:
        if args.batch_size < 1 or args.batch_size > 5000:
            raise RuntimeError("Batch size must be between 1 and 5000.")
        settings = Settings()
        _require_target(settings, args.confirm_production_target)
        backup = _validate_backup(args.backup_path, args.backup_sha256)
        source_engine = _source_engine()
        destination_engine = create_engine(settings.database_url, connect_args=settings.database_connect_args, poolclass=NullPool)
        if args.command == "import":
            if not args.execute or not args.confirm_import:
                raise RuntimeError("Import requires both --execute and --confirm-import.")
            report = execute_import(source_engine, destination_engine, settings, backup, args.batch_size)
        else:
            with source_engine.connect() as source_connection, destination_engine.connect() as destination_connection:
                report = build_plan(source_connection, destination_connection, settings, backup)
        print(json.dumps(report, sort_keys=True))
        return 0 if report.get("status") in {"safe_to_import", "imported"} else 2
    except Exception as exc:
        category = type(exc).__name__ if not isinstance(exc, SQLAlchemyError) else "database_error"
        print(json.dumps({"status": "blocked", "error_category": category}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
