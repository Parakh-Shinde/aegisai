from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
from time import monotonic

from fastapi import HTTPException, status
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings


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


class RedisLoginRateLimiter:
    """Shared login-abuse guard for staging and production API replicas."""

    def __init__(
        self,
        redis_url: str,
        *,
        max_failures: int = 5,
        window_seconds: int = 900,
        lock_seconds: int = 900,
    ) -> None:
        self.client = Redis.from_url(
            redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds

    def check(self, key: str) -> None:
        try:
            remaining = self.client.ttl(self._blocked_key(key))
        except RedisError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Sign-in protection is temporarily unavailable.",
            ) from exc
        if remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed sign-in attempts. Try again later.",
                headers={"Retry-After": str(remaining)},
            )

    def record_failure(self, key: str) -> None:
        failure_key = self._failure_key(key)
        try:
            failures = self.client.incr(failure_key)
            if failures == 1:
                self.client.expire(failure_key, self.window_seconds)
            if failures >= self.max_failures:
                self.client.setex(self._blocked_key(key), self.lock_seconds, "1")
        except RedisError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Sign-in protection is temporarily unavailable.",
            ) from exc

    def reset(self, key: str) -> None:
        try:
            self.client.delete(self._failure_key(key))
        except RedisError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Sign-in protection is temporarily unavailable.",
            ) from exc

    @staticmethod
    def _digest(key: str) -> str:
        return sha256(key.encode("utf-8")).hexdigest()

    def _failure_key(self, key: str) -> str:
        return f"aegisai:login:failures:{self._digest(key)}"

    def _blocked_key(self, key: str) -> str:
        return f"aegisai:login:blocked:{self._digest(key)}"


local_login_rate_limiter = LoginRateLimiter()


def get_login_rate_limiter() -> LoginRateLimiter | RedisLoginRateLimiter:
    settings = get_settings()
    if settings.redis_url:
        return RedisLoginRateLimiter(settings.redis_url)
    return local_login_rate_limiter
