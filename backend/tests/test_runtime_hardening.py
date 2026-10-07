import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import jwt  # noqa: E402
import pytest  # noqa: E402
from app.core.auth import create_access_token  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.execution import ModelCapacityError, ModelExecutionGate  # noqa: E402
from app.db.models import User, UserRole  # noqa: E402
from app.main import RequestBodyLimitMiddleware  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402


def test_production_requires_explicit_cors_and_trusted_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    encryption_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AEGISAI_EVIDENCE_ENCRYPTION_KEY", encryption_key)
    monkeypatch.delenv("AEGISAI_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("AEGISAI_TRUSTED_HOSTS", raising=False)

    with pytest.raises(RuntimeError, match="CORS"):
        get_settings()

    monkeypatch.setenv("AEGISAI_CORS_ORIGINS", "https://aegisai.example.com")
    with pytest.raises(RuntimeError, match="TRUSTED_HOSTS"):
        get_settings()


def test_jwt_has_audience_and_rejects_another_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    user = User(
        id="user-1",
        organization_id="organization-1",
        email="analyst@example.com",
        password_hash="not-used",
        role=UserRole.SECURITY_ANALYST,
    )
    token = create_access_token(user)

    claims = jwt.decode(
        token,
        "a" * 32,
        algorithms=["HS256"],
        audience="aegisai-api",
        issuer="aegisai",
    )
    assert claims["aud"] == "aegisai-api"
    assert claims["jti"]

    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            "a" * 32,
            algorithms=["HS256"],
            audience="another-service",
            issuer="aegisai",
        )


def test_model_execution_gate_rejects_excess_parallel_work() -> None:
    gate = ModelExecutionGate(max_concurrency=1)
    gate.acquire()

    with pytest.raises(ModelCapacityError):
        gate.acquire()

    gate.release()
    gate.acquire()
    gate.release()


def test_request_body_limit_rejects_chunked_oversized_requests() -> None:
    async def endpoint(scope, receive, send) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = RequestBodyLimitMiddleware(endpoint, max_body_bytes=8)
    messages = [
        {
            "type": "http.request",
            "body": b"0123456789",
            "more_body": False,
        }
    ]
    sent: list[dict] = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(
        middleware(
            {"type": "http", "headers": [], "method": "POST", "path": "/auth/login"},
            receive,
            send,
        )
    )

    assert sent[0]["status"] == 413
