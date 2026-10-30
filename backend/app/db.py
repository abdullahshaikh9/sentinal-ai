from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import Settings, get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()


def create_database_engine(database_settings: Settings):
    return create_engine(database_settings.database_url, connect_args=database_settings.database_connect_args)


engine = create_database_engine(settings)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class DatabaseUnavailableError(RuntimeError):
    """Raised when the configured database cannot accept a connection."""


def check_database_connection() -> None:
    """Verify the configured database without exposing credentials in the error."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise DatabaseUnavailableError(
            "The configured database is unavailable. Check DATABASE_URL and ensure the database server is running."
        ) from exc


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

