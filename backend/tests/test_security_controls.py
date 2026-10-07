import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402
from app.core.config import DEVELOPMENT_JWT_SECRET, get_settings  # noqa: E402
from app.core.evidence import protect_evidence, reveal_evidence  # noqa: E402
from app.core.rate_limit import LoginRateLimiter  # noqa: E402
from app.core.security import (  # noqa: E402
    require_api_key,
    validate_identifier,
    validate_local_http_url,
)
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
