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


def database_error_category(error: SQLAlchemyError) -> str:
    """Classify a database failure without exposing driver messages or secrets."""
    original = getattr(error, "orig", error)
    message = str(original).lower()
    if "doesn't exist" in message or "no such table" in message or "unknown table" in message:
        return "missing_table"
    if "access denied" in message or "authentication" in message:
        return "authentication_failure"
    if "permission" in message or "not authorized" in message:
        return "permission_denied"
    if "ssl" in message or "tls" in message or "certificate" in message:
        return "tls_error"
    if "name or service not known" in message or "getaddrinfo failed" in message or "unknown host" in message:
        return "dns_failure"
    if "connection refused" in message:
        return "connection_refused"
    if "timeout" in message:
        return "timeout"
    if "syntax error" in message or "unknown column" in message or "incompatible" in message:
        return "sql_incompatibility"
    if "connect" in message or "connection" in message or "server has gone away" in message:
        return "connection_error"
    if "duplicate" in message or "constraint" in message:
        return "constraint_violation"
    return "database_error"


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

