import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402
from app.core.config import DEVELOPMENT_JWT_SECRET, get_settings  # noqa: E402
from app.core.evidence import protect_evidence, reveal_evidence  # noqa: E402
from app.core.rate_limit import LoginRateLimiter, RedisLoginRateLimiter  # noqa: E402
from app.core.security import (  # noqa: E402
    require_agent_gateway_token,
    require_api_key,
    require_tool_runner_token,
    validate_identifier,
    validate_local_http_url,
)
from app.services import campaign_queue  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from fastapi import HTTPException  # noqa: E402


def test_identifier_validation_rejects_path_traversal() -> None:
    with pytest.raises(HTTPException):
        validate_identifier("../secret", "test_id")


def test_optional_api_key_allows_local_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISAI_API_KEY", raising=False)

    assert require_api_key(None) is None


def test_api_key_blocks_missing_or_invalid_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISAI_API_KEY", "expected-key")

    with pytest.raises(HTTPException):
        require_api_key(None)

    with pytest.raises(HTTPException):
        require_api_key("wrong-key")

    assert require_api_key("expected-key") is None


def test_agent_gateway_token_blocks_missing_or_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_AGENT_GATEWAY_TOKEN", "agent-gateway-test-token")

    with pytest.raises(HTTPException):
        require_agent_gateway_token(None)

    with pytest.raises(HTTPException):
        require_agent_gateway_token("wrong-token")

    assert require_agent_gateway_token("agent-gateway-test-token") is None


def test_tool_runner_token_blocks_missing_or_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_TOOL_RUNNER_TOKEN", "tool-runner-test-token")

    with pytest.raises(HTTPException):
        require_tool_runner_token(None)

    with pytest.raises(HTTPException):
        require_tool_runner_token("wrong-token")

    assert require_tool_runner_token("tool-runner-test-token") is None


def test_ollama_url_rejects_remote_hosts_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISAI_ALLOW_REMOTE_OLLAMA", raising=False)

    with pytest.raises(ValueError):
        validate_local_http_url("https://example.com")


def test_ollama_url_allows_local_and_exact_wsl_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert validate_local_http_url("http://127.0.0.1:11434") == (
        "http://127.0.0.1:11434"
    )
    monkeypatch.setenv(
        "AEGISAI_LOCAL_MODEL_ENDPOINTS",
        "http://172.22.160.1:11434",
    )
    assert validate_local_http_url("http://172.22.160.1:11434") == (
        "http://172.22.160.1:11434"
    )
    with pytest.raises(ValueError):
        validate_local_http_url("http://172.8.1.1:11434")


def test_remote_endpoint_requires_exact_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ALLOW_REMOTE_OLLAMA", "true")
    monkeypatch.setenv(
        "AEGISAI_APPROVED_MODEL_ENDPOINTS",
        "https://models.example.com/ollama",
    )
    monkeypatch.setattr("app.core.security._require_public_endpoint", lambda *_: None)

    assert validate_local_http_url("https://models.example.com/ollama/") == (
        "https://models.example.com/ollama"
    )
    with pytest.raises(ValueError):
        validate_local_http_url("https://models.example.com/other")


def test_production_rejects_the_known_development_jwt_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegisai:password@postgres:5432/aegisai",
    )
    monkeypatch.setenv("AEGISAI_JWT_SECRET", DEVELOPMENT_JWT_SECRET)
    monkeypatch.setenv("AEGISAI_EVIDENCE_ENCRYPTION_KEY", "a" * 44)

    with pytest.raises(RuntimeError, match="unique value"):
        get_settings()


def test_evidence_is_encrypted_when_a_key_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encryption_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AEGISAI_EVIDENCE_ENCRYPTION_KEY", encryption_key)

    protected = protect_evidence("sensitive prompt")

    assert protected != "sensitive prompt"
    assert protected.startswith("fernet:v1:")
    assert reveal_evidence(protected) == "sensitive prompt"


def test_login_rate_limiter_blocks_after_repeated_failures() -> None:
    limiter = LoginRateLimiter(max_failures=2, window_seconds=60, lock_seconds=60)

    limiter.record_failure("127.0.0.1:user@example.com")
    limiter.record_failure("127.0.0.1:user@example.com")

    with pytest.raises(HTTPException) as exc_info:
        limiter.check("127.0.0.1:user@example.com")

    assert exc_info.value.status_code == 429


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    def ttl(self, key: str) -> int:
        return self.ttls.get(key, -2)

    def incr(self, key: str) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    def setex(self, key: str, seconds: int, value: str) -> None:
        del value
        self.ttls[key] = seconds

    def delete(self, key: str) -> None:
        self.values.pop(key, None)
        self.ttls.pop(key, None)


def test_redis_login_rate_limiter_hashes_identity_and_blocks() -> None:
    limiter = RedisLoginRateLimiter("redis://unused", max_failures=2)
    limiter.client = FakeRedis()
    key = "198.51.100.25:analyst@example.com"

    limiter.record_failure(key)
    limiter.record_failure(key)

    assert "analyst@example.com" not in limiter._failure_key(key)
    with pytest.raises(HTTPException) as exc_info:
        limiter.check(key)
    assert exc_info.value.status_code == 429


def test_campaign_job_status_never_returns_redis_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeJob:
        id = "job-1"
        meta = {
            "organization_id": "organization-1",
            "campaign_id": "campaign-1",
            "model": "local-model",
        }
        result = {"prompt_sent": "sensitive evidence"}

        @staticmethod
        def get_status() -> str:
            return "finished"

    monkeypatch.setattr(campaign_queue, "_connection", lambda: object())
    monkeypatch.setattr(campaign_queue.Job, "fetch", lambda *args, **kwargs: FakeJob())

    status = campaign_queue.get_campaign_job("job-1", "organization-1")

    assert status.campaign_id == "campaign-1"
    assert status.model == "local-model"
    assert not hasattr(status, "result")
    with pytest.raises(PermissionError):
        campaign_queue.get_campaign_job("job-1", "organization-2")
