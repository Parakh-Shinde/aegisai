"""Regression tests for the production configuration contract.

These tests exercise configuration validation without starting the API or
connecting to external services. The hostnames and credentials are deliberately
non-routable test values; they are not deployment secrets.
"""

import pytest

from app.core.config import get_settings

from cryptography.fernet import Fernet


def _set_valid_production_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set every required production setting to a valid test value."""
    values = {
        "AEGISAI_ENVIRONMENT": "production",
        "AEGISAI_EXPOSE_API_DOCS": "false",
        "AEGISAI_AUTH_REQUIRED": "true",
        "DATABASE_URL": "postgresql+psycopg://test:test@postgres.invalid/aegisai",
        "AEGISAI_JWT_SECRET": "test-jwt-secret-" + ("x" * 40),
        "AEGISAI_CORS_ORIGINS": "https://console.example.test",
        "AEGISAI_TRUSTED_HOSTS": "console.example.test,api.example.test",
        "AEGISAI_REDIS_URL": "redis://redis.invalid:6379/0",
        "AEGISAI_ASYNC_CAMPAIGNS": "true",
        "AEGISAI_AGENT_GATEWAY_TOKEN": "g" * 48,
        "AEGISAI_TOOL_RUNNER_TOKEN": "t" * 48,
        "AEGISAI_BOOTSTRAP_TOKEN": "b" * 48,
        "AEGISAI_AGENT_ENFORCEMENT_MODE": "enforce",
        "AEGISAI_OCR_ENABLED": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    monkeypatch.setenv(
        "AEGISAI_EVIDENCE_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setenv(
        "AEGISAI_MFA_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )


def test_valid_production_configuration_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)

    settings = get_settings()

    assert settings.is_production
    assert settings.auth_required is True
    assert settings.api_docs_enabled is False
    assert settings.async_campaigns is True
    assert settings.agent_enforcement_mode == "enforce"


def test_production_rejects_exposed_api_documentation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)
    monkeypatch.setenv("AEGISAI_EXPOSE_API_DOCS", "true")

    with pytest.raises(RuntimeError, match="EXPOSE_API_DOCS"):
        get_settings()


def test_production_rejects_short_jwt_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "too-short")

    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        get_settings()


def test_production_rejects_wildcard_cors_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)
    monkeypatch.setenv(
        "AEGISAI_CORS_ORIGINS",
        "https://console.example.test,*",
    )

    with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
        get_settings()


def test_production_rejects_observe_only_agent_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)
    monkeypatch.setenv("AEGISAI_AGENT_ENFORCEMENT_MODE", "observe")

    with pytest.raises(RuntimeError, match="must be enforce"):
        get_settings()


def test_production_rejects_invalid_mfa_encryption_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_production_environment(monkeypatch)
    monkeypatch.setenv("AEGISAI_MFA_ENCRYPTION_KEY", "not-a-valid-fernet-key")

    with pytest.raises(RuntimeError, match="MFA_ENCRYPTION_KEY"):
        get_settings()
