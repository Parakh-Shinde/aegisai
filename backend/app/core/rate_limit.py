from dataclasses import dataclass
from threading import Lock
from time import monotonic

from fastapi import HTTPException, status


@dataclass
class LoginAttempt:
    failures: int = 0
    window_started_at: float = 0.0
    blocked_until: float = 0.0


class LoginRateLimiter:
    """Small process-local guard for login abuse.

    Production deployments with multiple API replicas must enforce the same policy
    at the edge or through a shared store such as Redis.
    """

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: int = 900,
        lock_seconds: int = 900,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds
        self._attempts: dict[str, LoginAttempt] = {}
        self._lock = Lock()

    def check(self, key: str) -> None:
        now = monotonic()
        with self._lock:
            attempt = self._attempts.get(key)
            if attempt and attempt.blocked_until > now:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed sign-in attempts. Try again later.",
                    headers={"Retry-After": str(int(attempt.blocked_until - now) + 1)},
                )

    def record_failure(self, key: str) -> None:
        now = monotonic()
        with self._lock:
            attempt = self._attempts.setdefault(
                key,
                LoginAttempt(window_started_at=now),
            )
            if now - attempt.window_started_at >= self.window_seconds:
                attempt.failures = 0
                attempt.window_started_at = now
                attempt.blocked_until = 0.0
            attempt.failures += 1
            if attempt.failures >= self.max_failures:
                attempt.blocked_until = now + self.lock_seconds

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
