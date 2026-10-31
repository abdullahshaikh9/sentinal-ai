"""Guarded, non-destructive release migration for the production deployment."""

from __future__ import annotations

import logging
import argparse
from pathlib import Path
from urllib.parse import urlsplit

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import inspect
from sqlalchemy.pool import NullPool

from app.config import BACKEND_DIR, get_settings
from app.db import database_error_category


logger = logging.getLogger("sentinel.migration_release")
EXPECTED_HOST = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com"
EXPECTED_DATABASE = "sentinel_ai"
EXPECTED_PARENT = "20261028_0009"
EXPECTED_HEAD = "20261030_0010"
MIGRATION_LOCK_NAME = "sentinel_ai_alembic_migration"


def _target_is_expected(database_url: str) -> bool:
    parsed = urlsplit(database_url)
    return parsed.hostname == EXPECTED_HOST and parsed.port == 4000 and parsed.path.lstrip("/") == EXPECTED_DATABASE


def _validate_initialization_target(settings, *, confirmed: bool, initialize_empty: bool) -> None:
    if not confirmed or not initialize_empty:
        raise RuntimeError("Empty production initialization requires both explicit confirmation flags.")
    if not _target_is_expected(settings.database_url):
        raise RuntimeError("Configured database target is not the approved production TiDB target.")
    ca_path = settings.database_ssl_ca_path
    if not ca_path or not Path(ca_path).is_file():
        raise RuntimeError("Configured TiDB CA certificate is missing or unreadable.")
    connect_args = settings.database_connect_args
    if connect_args.get("ssl_verify_cert") is not True or connect_args.get("ssl_verify_identity") is not True:
        raise RuntimeError("TiDB certificate and hostname verification are not enabled.")


def _verify_empty_schema(connection) -> None:
    server_database = connection.execute(text("SELECT DATABASE()")).scalar_one()
    if server_database != EXPECTED_DATABASE:
        raise RuntimeError("Connected database identity does not match the approved production database.")

    inspector = inspect(connection)
    tables = sorted(inspector.get_table_names())
    views = sorted(inspector.get_view_names())
    if tables:
        raise RuntimeError("Production initialization refused because existing tables were found.")
    if views:
        raise RuntimeError("Production initialization refused because existing views were found.")

    current_heads = tuple(MigrationContext.configure(connection).get_current_heads())
    if current_heads:
        raise RuntimeError("Production initialization refused because an Alembic revision already exists.")


def initialize_empty_production(*, confirm_production_target: bool = False, initialize_empty: bool = False) -> int:
    settings = get_settings()
    try:
        _validate_initialization_target(settings, confirmed=confirm_production_target, initialize_empty=initialize_empty)
        engine = create_engine(settings.database_url, connect_args=settings.database_connect_args, poolclass=NullPool)
        with engine.connect() as connection:
            lock_acquired = connection.execute(text("SELECT GET_LOCK(:lock_name, 1)"), {"lock_name": MIGRATION_LOCK_NAME}).scalar()
            if lock_acquired != 1:
                logger.error("Empty production initialization refused: another migration process holds the database lock.")
                return 2
            try:
                _verify_empty_schema(connection)
                connection.commit()
                alembic_config = Config(str(BACKEND_DIR / "alembic.ini"))
                alembic_config.set_main_option("prepend_sys_path", str(BACKEND_DIR))
                command.upgrade(alembic_config, EXPECTED_HEAD)
                current_heads = tuple(MigrationContext.configure(connection).get_current_heads())
                if current_heads != (EXPECTED_HEAD,):
                    raise RuntimeError("Initialization completed without reaching the expected Alembic head.")
                logger.info("Empty production initialization completed to the expected migration head.")
                return 0
            finally:
                connection.execute(text("SELECT RELEASE_LOCK(:lock_name)"), {"lock_name": MIGRATION_LOCK_NAME})
    except Exception as exc:
        category = database_error_category(exc) if isinstance(exc, SQLAlchemyError) else type(exc).__name__
        logger.error("Empty production initialization failed: category=%s", category)
        return 2


def run(confirm_production_target: bool = False) -> int:
    settings = get_settings()
    if not confirm_production_target:
        logger.error("Guarded release migration refused: pass --confirm-production-target from a reviewed runtime release command.")
        return 2
    if not _target_is_expected(settings.database_url):
        logger.error("Guarded release migration refused: configured database target is not the approved production TiDB target.")
        return 2

    engine = create_engine(settings.database_url, connect_args=settings.database_connect_args)
    try:
        with engine.connect() as connection:
            try:
                lock_acquired = connection.execute(text("SELECT GET_LOCK(:lock_name, 1)"), {"lock_name": MIGRATION_LOCK_NAME}).scalar()
                if lock_acquired != 1:
                    logger.error("Guarded release migration refused: another migration process holds the database lock.")
                    return 2
                current_heads = MigrationContext.configure(connection).get_current_heads()
                if current_heads == (EXPECTED_HEAD,):
                    logger.info("Production database is already at the expected migration head.")
                    return 0
                if current_heads != (EXPECTED_PARENT,):
                    logger.error("Guarded release migration refused: database must be exactly at the reviewed parent revision before migration.")
                    return 2

                alembic_config = Config(str(BACKEND_DIR / "alembic.ini"))
                alembic_config.set_main_option("prepend_sys_path", str(BACKEND_DIR))
                command.upgrade(alembic_config, EXPECTED_HEAD)
                logger.info("Guarded release migration completed to the expected head.")
                return 0
            finally:
                if 'lock_acquired' in locals() and lock_acquired == 1:
                    connection.execute(text("SELECT RELEASE_LOCK(:lock_name)"), {"lock_name": MIGRATION_LOCK_NAME})
    except Exception as exc:
        category = database_error_category(exc) if isinstance(exc, SQLAlchemyError) else type(exc).__name__
        logger.error("Guarded release migration failed: category=%s", category)
        return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a reviewed Sentinel AI production migration once.")
    parser.add_argument("--confirm-production-target", action="store_true")
    parser.add_argument("--initialize-empty-production", action="store_true")
    args = parser.parse_args()
    if args.initialize_empty_production:
        raise SystemExit(initialize_empty_production(confirm_production_target=args.confirm_production_target, initialize_empty=True))
    raise SystemExit(run(confirm_production_target=args.confirm_production_target))
