"""Guarded, non-destructive release migration for the production deployment."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from app.config import BACKEND_DIR, get_settings


logger = logging.getLogger("sentinel.migration_release")
EXPECTED_HOST = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com"
EXPECTED_DATABASE = "sentinel_ai"
EXPECTED_PARENT = "20261028_0009"
EXPECTED_HEAD = "20261030_0010"


def _target_is_expected(database_url: str) -> bool:
    parsed = urlsplit(database_url)
    return parsed.hostname == EXPECTED_HOST and parsed.port == 4000 and parsed.path.lstrip("/") == EXPECTED_DATABASE


def run() -> int:
    settings = get_settings()
    if not settings.migration_release_enabled:
        logger.info("Guarded release migration is disabled; no schema changes were attempted.")
        return 0
    if not _target_is_expected(settings.database_url):
        logger.error("Guarded release migration refused: configured database target is not the approved production TiDB target.")
        return 2

    engine = create_engine(settings.database_url, connect_args=settings.database_connect_args)
    with engine.connect() as connection:
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


if __name__ == "__main__":
    raise SystemExit(run())
