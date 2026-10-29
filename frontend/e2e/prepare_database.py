"""Prepare a disposable SQLite database for local browser smoke tests only."""

from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
import sys
from tempfile import gettempdir


BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(BACKEND_DIR)

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.models import User  # noqa: E402
from app.services.auth import hash_password  # noqa: E402


email = os.environ["SENTINEL_E2E_EMAIL"]
password = os.environ["SENTINEL_E2E_PASSWORD"]
database_url = os.environ.get("DATABASE_URL", "")
if not database_url.startswith("sqlite:///"):
    raise RuntimeError("E2E setup requires its isolated SQLite DATABASE_URL.")
database_file = Path(database_url.removeprefix("sqlite:///"))
if database_file.name != "browser-test.sqlite3" or database_file.parent.parent.resolve() != Path(gettempdir()).resolve() or not database_file.parent.name.startswith("sentinel-ai-e2e-"):
    raise RuntimeError("E2E setup refuses database files outside its generated temporary directory.")

# Match the isolated in-memory SQLite fixture strategy used by backend tests.
# Migration compatibility is checked separately against the real configured DB.
Base.metadata.create_all(engine)
with SessionLocal() as db:
    db.add(
        User(
            email=email,
            display_name="Isolated Browser Test User",
            password_hash=hash_password(password),
            phone_number="+15550000001",
            email_verified_at=datetime.now(UTC),
            phone_verified_at=datetime.now(UTC),
            is_active=True,
        )
    )
    db.commit()
