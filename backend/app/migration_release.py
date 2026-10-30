"""Guarded, non-destructive release migration for the production deployment."""

from __future__ import annotations

import logging
import argparse
from urllib.parse import urlsplit

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

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
    parser = argparse.ArgumentParser(description="Run the reviewed Sentinel AI production migration once.")
    parser.add_argument("--confirm-production-target", action="store_true", required=True)
    raise SystemExit(run(confirm_production_target=parser.parse_args().confirm_production_target))
