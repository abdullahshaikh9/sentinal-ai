"""In-memory, one-time access control for the temporary admin diagnostics flow."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
from threading import Lock


class DiagnosticChallengeManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self._challenges: dict[str, datetime] = {}
        self._attempts: dict[str, deque[datetime]] = defaultdict(deque)

    def _allow_attempt(self, client_key: str, limit: int, window: timedelta, now: datetime) -> bool:
        attempts = self._attempts[client_key]
        cutoff = now - window
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        return True

    def issue(self, client_key: str, secret: str, expected_secret: str, ttl_seconds: int, limit: int) -> str | None:
        now = datetime.now(UTC)
        with self._lock:
            if not self._allow_attempt(client_key, limit, timedelta(minutes=15), now):
                return None
            if not expected_secret or not hmac.compare_digest(secret, expected_secret):
                return None
            raw = secrets.token_urlsafe(32)
            self._challenges[hashlib.sha256(raw.encode()).hexdigest()] = now + timedelta(seconds=ttl_seconds)
            return raw

    def consume(self, client_key: str, challenge: str, limit: int) -> bool:
        now = datetime.now(UTC)
        digest = hashlib.sha256(challenge.encode()).hexdigest()
        with self._lock:
            if not self._allow_attempt(client_key, limit, timedelta(minutes=15), now):
                return False
            expires_at = self._challenges.pop(digest, None)
            return expires_at is not None and expires_at > now


diagnostic_challenges = DiagnosticChallengeManager()
