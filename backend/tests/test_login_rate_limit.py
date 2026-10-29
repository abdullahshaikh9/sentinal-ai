from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

from fastapi import HTTPException, Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import LoginAttempt, LoginRateLimitMutex
from app.services.auth import _rate_keys, finalize_login_attempt, reserve_login_attempt


def request_for(host: str = "192.0.2.44") -> Request:
    return Request({
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/auth/login",
        "raw_path": b"/api/v1/auth/login",
        "query_string": b"",
        "headers": [],
        "client": (host, 42000),
        "server": ("testserver", 80),
    })


def session_factory(path):
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as db:
        db.add(LoginRateLimitMutex(id=1))
        db.commit()
    return engine, factory


def test_concurrent_login_reservations_cannot_exceed_limit(tmp_path) -> None:
    engine, factory = session_factory(tmp_path / "login-limit.sqlite")
    barrier = Barrier(12)

    def fail_login() -> str:
        barrier.wait(timeout=5)
        with factory() as db:
            try:
                reservation = reserve_login_attempt(request_for(), "atomic@example.test", db)
            except HTTPException as exc:
                assert exc.status_code == 429
                return "blocked"
            finalize_login_attempt(reservation, db, outcome="failed")
            return "accepted"

    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: fail_login(), range(12)))
        assert results.count("accepted") == 5
        assert results.count("blocked") == 7
        with factory() as db:
            rows = db.scalars(select(LoginAttempt)).all()
            assert len(rows) == 15
            assert {row.state for row in rows} == {"failed"}
            assert all("atomic@example.test" not in row.attempt_key for row in rows)
    finally:
        engine.dispose()


def test_expired_login_attempts_are_removed_before_reservation(tmp_path) -> None:
    engine, factory = session_factory(tmp_path / "login-expiry.sqlite")
    request = request_for()
    keys = _rate_keys(request, "expired@example.test")
    stale_time = datetime.now(UTC) - timedelta(minutes=11)
    try:
        with factory() as db:
            db.add_all(LoginAttempt(attempt_id="stale", attempt_key=key, state="failed", created_at=stale_time) for key in keys)
            db.commit()
        with factory() as db:
            reservation = reserve_login_attempt(request, "expired@example.test", db)
            finalize_login_attempt(reservation, db, outcome="failed")
        with factory() as db:
            rows = db.scalars(select(LoginAttempt)).all()
            assert len(rows) == 3
            assert all(row.attempt_id != "stale" for row in rows)
            assert {row.state for row in rows} == {"failed"}
    finally:
        engine.dispose()


def test_success_releases_reservation_and_clears_account_failures(tmp_path) -> None:
    engine, factory = session_factory(tmp_path / "login-success.sqlite")
    request = request_for()
    keys = _rate_keys(request, "success@example.test")
    try:
        with factory() as db:
            for index in range(2):
                reservation = reserve_login_attempt(request, "success@example.test", db)
                finalize_login_attempt(reservation, db, outcome="failed")
            reservation = reserve_login_attempt(request, "success@example.test", db)
            finalize_login_attempt(reservation, db, outcome="success")
        with factory() as db:
            rows = db.scalars(select(LoginAttempt)).all()
            assert {row.attempt_key for row in rows} == {keys[2]}
            assert len(rows) == 2
            assert all(row.state == "failed" for row in rows)
    finally:
        engine.dispose()
