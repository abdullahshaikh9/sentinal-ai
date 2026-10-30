from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.db import Base
from app import models  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata
settings = get_settings()


def run_migrations_offline() -> None:
    context.configure(url=settings.database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(settings.database_url, connect_args=settings.database_connect_args, poolclass=pool.NullPool)
    try:
        with connectable.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()
    except SQLAlchemyError as exc:
        raise RuntimeError(
            "Alembic could not connect to the configured database. Check DATABASE_URL and ensure the database server is running."
        ) from exc


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

