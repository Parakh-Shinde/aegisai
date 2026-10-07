import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402
from app.core.security import (  # noqa: E402
    require_api_key,
    validate_identifier,
    validate_local_http_url,
)
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


def test_ollama_url_allows_local_and_wsl_hosts() -> None:
    assert validate_local_http_url("http://127.0.0.1:11434") == (
        "http://127.0.0.1:11434"
    )
    assert validate_local_http_url("http://172.22.160.1:11434") == (
        "http://172.22.160.1:11434"
    )


def test_remote_endpoint_requires_exact_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ALLOW_REMOTE_OLLAMA", "true")
    monkeypatch.setenv(
        "AEGISAI_APPROVED_MODEL_ENDPOINTS",
        "https://models.example.com/ollama",
    )

    assert validate_local_http_url("https://models.example.com/ollama/") == (
        "https://models.example.com/ollama"
    )
    with pytest.raises(ValueError):
        validate_local_http_url("https://models.example.com/other")
