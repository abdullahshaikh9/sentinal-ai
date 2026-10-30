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
from app.config import Settings, get_settings
from app.db import Base
from app.migration_release import EXPECTED_DATABASE, EXPECTED_HEAD, EXPECTED_HOST, _target_is_expected, run as run_migration


REQUIRED_TABLE_NAMES = tuple(sorted(set(Base.metadata.tables) | {"alembic_version"}))
EXPECTED_INDEXES: dict[str, tuple[str, ...]] = {
    "activity_events": ("ix_activity_events_created_at", "ix_activity_events_event_type", "ix_activity_events_finding_id", "ix_activity_events_owner_id", "ix_activity_events_scan_id"),
    "assets": ("ix_assets_owner_id", "uq_assets_owner_normalized_url"),
    "auth_sessions": ("ix_auth_sessions_expires_at", "ix_auth_sessions_user_id", "token_hash"),
    "findings": ("ix_findings_scan_id", "uq_findings_scan_dedup_key"),
    "finding_remediation": ("ix_finding_remediation_owner_id",),
    "login_attempts": ("ix_login_attempts_created_at", "ix_login_attempts_key_created", "uq_login_attempt_id_key"),
    "login_rate_limit_mutex": (),
    "notifications": ("ix_notifications_created_at", "ix_notifications_finding_id", "ix_notifications_scan_id", "ix_notifications_user_id"),
    "otp_challenges": ("ix_otp_challenges_expires_at", "ix_otp_challenges_registration_token_hash", "ix_otp_challenges_user_id"),
    "otp_send_attempts": ("ix_otp_send_attempts_created_at", "ix_otp_send_attempts_ip_hash", "ix_otp_send_attempts_recipient_hash"),
    "password_reset_challenges": ("ix_password_reset_challenges_expires_at", "ix_password_reset_challenges_user_id", "uq_password_reset_challenges_request_token_hash", "uq_password_reset_challenges_reset_token_hash"),
    "remediation_changes": ("ix_remediation_changes_finding_id", "ix_remediation_changes_owner_id"),
    "report_metadata": ("ix_report_metadata_scan_id",),
    "scans": ("ix_scans_asset_id", "ix_scans_owner_id"),
    "users": ("email", "uq_users_phone_number"),
    "verification_attempts": ("ix_verification_attempts_finding_id", "ix_verification_attempts_scan_id"),
}
MAX_DIAGNOSTIC_SCHEMA_ISSUES = 100


def _configured_identity(settings: Settings, connection) -> dict[str, object]:
    parsed = urlsplit(settings.database_url)
    identity = {
        "configured_host": parsed.hostname,
        "configured_port": parsed.port,
        "configured_database": parsed.path.lstrip("/"),
        "expected_host": EXPECTED_HOST,
        "expected_port": 4000,
        "expected_database": EXPECTED_DATABASE,
        "engine": connection.dialect.name,
    }
    if connection.dialect.name == "mysql":
        identity["server_database"] = connection.execute(text("SELECT DATABASE()")).scalar_one()
        identity["server_database_matches_config"] = identity["server_database"] == identity["configured_database"]
    return identity


def _schema_issues(connection) -> list[str]:
    inspector = inspect(connection)
    actual_tables = set(inspector.get_table_names())
    issues: list[str] = []
    for name, table in sorted(Base.metadata.tables.items()):
        if name not in actual_tables:
            issues.append(f"missing_table:{name}")
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(name)}
        for column in table.columns:
            if column.name not in actual_columns:
                issues.append(f"missing_column:{name}.{column.name}")
        actual_indexes = {index["name"] for index in inspector.get_indexes(name) if index.get("name")}
        actual_indexes.update(constraint["name"] for constraint in inspector.get_unique_constraints(name) if constraint.get("name"))
        for index_name in EXPECTED_INDEXES.get(name, ()):
            if index_name not in actual_indexes:
                issues.append(f"missing_index:{name}.{index_name}")
    if "alembic_version" not in actual_tables:
        issues.append("missing_table:alembic_version")
    return issues


def collect_diagnostic_report(connection, settings: Settings) -> dict[str, object]:
    """Collect bounded, read-only diagnostics using only metadata and COUNT queries."""
    inspector = inspect(connection)
    actual_tables = set(inspector.get_table_names())
    required_tables = {name: name in actual_tables for name in REQUIRED_TABLE_NAMES}
    revisions = list(MigrationContext.configure(connection).get_current_heads()) if "alembic_version" in actual_tables else []
    row_counts: dict[str, int] = {}
    for name in REQUIRED_TABLE_NAMES:
        if name in actual_tables:
            row_counts[name] = int(connection.execute(text(f"SELECT COUNT(*) FROM `{name}`")).scalar_one())
    all_issues = _schema_issues(connection)
    issues = all_issues[:MAX_DIAGNOSTIC_SCHEMA_ISSUES]
    return {
        "database": "healthy",
        "database_identity": _configured_identity(settings, connection),
        "tls": {
            "ca_configured": bool(settings.database_ssl_ca_path),
            "certificate_verification": settings.database_connect_args.get("ssl_verify_cert") is True,
            "hostname_verification": settings.database_connect_args.get("ssl_verify_identity") is True,
        },
        "required_tables": required_tables,
        "current_revision": revisions[0] if len(revisions) == 1 else None,
        "current_revisions": revisions,
        "expected_head": EXPECTED_HEAD,
        "revision_state": "at_head" if revisions == [EXPECTED_HEAD] else ("missing_revision_table" if "alembic_version" not in actual_tables else "behind_or_diverged"),
        "row_counts": row_counts,
        "schema_compatible": not all_issues,
        "schema_issues": issues,
    }


def validate_confirmed_target(settings: Settings) -> None:
    """Validate the exact production target before any diagnostic SQL runs."""
    if not _target_is_expected(settings.database_url):
        raise RuntimeError("The configured database is not the approved production TiDB target.")
    ca_path = settings.database_ssl_ca_path
    if not ca_path or not Path(ca_path).is_file():
        raise RuntimeError("The configured TiDB CA certificate is missing or unreadable.")
    connect_args = settings.database_connect_args
    if connect_args.get("ssl_verify_cert") is not True or connect_args.get("ssl_verify_identity") is not True:
        raise RuntimeError("TiDB certificate and hostname verification are not enabled.")


def _require_confirmed_target(confirmed: bool):
    settings = get_settings()
    if not confirmed:
        raise RuntimeError("Pass --confirm-production-target from the reviewed production runtime.")
    parsed = urlsplit(settings.database_url)
    validate_confirmed_target(settings)
    return settings, parsed


def _snapshot(connection) -> dict[str, object]:
    return collect_diagnostic_report(connection, get_settings())


def _schema_snapshot(connection) -> dict[str, object]:
    inspector = inspect(connection)
    result: dict[str, object] = {}
    for name, table in sorted(Base.metadata.tables.items()):
        if not inspector.has_table(name):
            result[name] = {"exists": False, "missing_columns": sorted(column.name for column in table.columns), "missing_indexes": sorted(index.name for index in table.indexes if index.name)}
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(name)}
        actual_indexes = {index["name"] for index in inspector.get_indexes(name) if index.get("name")}
        actual_indexes.update(constraint["name"] for constraint in inspector.get_unique_constraints(name) if constraint.get("name"))
        result[name] = {
            "exists": True,
            "missing_columns": sorted(column.name for column in table.columns if column.name not in actual_columns),
            "missing_indexes": sorted(index_name for index_name in EXPECTED_INDEXES.get(name, ()) if index_name not in actual_indexes),
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
