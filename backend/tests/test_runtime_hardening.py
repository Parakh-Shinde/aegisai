import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import jwt
import pytest
from cryptography.fernet import Fernet

from app.core.auth import create_access_token
from app.core.config import get_settings
from app.core.execution import ModelCapacityError, ModelExecutionGate
from app.db.models import User, UserRole
from app.main import RequestBodyLimitMiddleware


def test_production_requires_explicit_cors_and_trusted_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
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


def test_default_trusted_hosts_include_internal_tool_runner_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISAI_TRUSTED_HOSTS", raising=False)

    assert "api" in get_settings().trusted_hosts


def test_release_evidence_age_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISAI_RELEASE_EVIDENCE_MAX_AGE_HOURS", "24")
    assert get_settings().release_evidence_max_age_hours == 24

    monkeypatch.setenv("AEGISAI_RELEASE_EVIDENCE_MAX_AGE_HOURS", "0")
    with pytest.raises(RuntimeError, match="RELEASE_EVIDENCE_MAX_AGE_HOURS"):
        get_settings()


def test_production_requires_redis_and_async_campaigns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    monkeypatch.setenv(
        "AEGISAI_EVIDENCE_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
    )
    monkeypatch.setenv("AEGISAI_CORS_ORIGINS", "https://aegisai.example.com")
    monkeypatch.setenv("AEGISAI_TRUSTED_HOSTS", "aegisai.example.com")
    monkeypatch.delenv("AEGISAI_REDIS_URL", raising=False)
    monkeypatch.setenv("AEGISAI_ASYNC_CAMPAIGNS", "true")

    with pytest.raises(RuntimeError, match="REDIS_URL"):
        get_settings()

    monkeypatch.setenv("AEGISAI_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("AEGISAI_ASYNC_CAMPAIGNS", "false")
    with pytest.raises(RuntimeError, match="ASYNC_CAMPAIGNS"):
        get_settings()


def test_production_rejects_non_postgresql_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./aegisai.db")

    with pytest.raises(RuntimeError, match="PostgreSQL"):
        get_settings()


def test_production_requires_agent_gateway_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    monkeypatch.setenv(
        "AEGISAI_EVIDENCE_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
    )
    monkeypatch.setenv("AEGISAI_CORS_ORIGINS", "https://aegisai.example.com")
    monkeypatch.setenv("AEGISAI_TRUSTED_HOSTS", "aegisai.example.com")
    monkeypatch.setenv("AEGISAI_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("AEGISAI_ASYNC_CAMPAIGNS", "true")
    monkeypatch.setenv("AEGISAI_TOOL_RUNNER_TOKEN", "b" * 32)
    monkeypatch.delenv("AEGISAI_AGENT_GATEWAY_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="AGENT_GATEWAY_TOKEN"):
        get_settings()


def test_production_requires_tool_runner_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    monkeypatch.setenv(
        "AEGISAI_EVIDENCE_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
    )
    monkeypatch.setenv("AEGISAI_CORS_ORIGINS", "https://aegisai.example.com")
    monkeypatch.setenv("AEGISAI_TRUSTED_HOSTS", "aegisai.example.com")
    monkeypatch.setenv("AEGISAI_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("AEGISAI_ASYNC_CAMPAIGNS", "true")
    monkeypatch.setenv("AEGISAI_AGENT_GATEWAY_TOKEN", "b" * 32)
    monkeypatch.delenv("AEGISAI_TOOL_RUNNER_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="TOOL_RUNNER_TOKEN"):
        get_settings()


def test_production_requires_independent_mfa_encryption_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    monkeypatch.setenv(
        "AEGISAI_EVIDENCE_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
    )
    monkeypatch.setenv("AEGISAI_CORS_ORIGINS", "https://aegisai.example.com")
    monkeypatch.setenv("AEGISAI_TRUSTED_HOSTS", "aegisai.example.com")
    monkeypatch.setenv("AEGISAI_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("AEGISAI_ASYNC_CAMPAIGNS", "true")
    monkeypatch.setenv("AEGISAI_AGENT_GATEWAY_TOKEN", "a" * 32)
    monkeypatch.setenv("AEGISAI_TOOL_RUNNER_TOKEN", "b" * 32)
    monkeypatch.setenv("AEGISAI_OCR_ENABLED", "false")
    monkeypatch.delenv("AEGISAI_MFA_ENCRYPTION_KEY", raising=False)

    with pytest.raises(RuntimeError, match="MFA_ENCRYPTION_KEY"):
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


def test_api_docs_are_enabled_by_default_in_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "development")
    monkeypatch.delenv("AEGISAI_EXPOSE_API_DOCS", raising=False)

    assert get_settings().api_docs_enabled is True


def test_production_rejects_explicitly_enabled_api_docs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_EXPOSE_API_DOCS", "true")

    with pytest.raises(
        RuntimeError,
        match="AEGISAI_EXPOSE_API_DOCS must be false in production",
    ):
        get_settings()
