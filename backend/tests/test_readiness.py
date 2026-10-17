import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from app import main
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError


def configure_database(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    session = MagicMock()
    session.__enter__.return_value = session
    monkeypatch.setattr(
        main,
        "SessionLocal",
        MagicMock(return_value=session),
    )
    return session


def configure_settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    async_campaigns: bool = False,
    redis_url: str | None = None,
) -> None:
    monkeypatch.setattr(
        main,
        "settings",
        SimpleNamespace(
            async_campaigns=async_campaigns,
            redis_url=redis_url,
        ),
    )


def response_json(response) -> dict:
    return json.loads(response.body)


def test_readiness_returns_200_when_database_is_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database(monkeypatch)
    configure_settings(monkeypatch)

    response = main.readiness_check()

    assert response.status_code == 200
    assert response_json(response) == {
        "status": "ok",
        "checks": {"database": "ok"},
    }


def test_readiness_returns_503_when_database_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = configure_database(monkeypatch)
    session.execute.side_effect = SQLAlchemyError("database unavailable")
    configure_settings(monkeypatch)

    response = main.readiness_check()

    assert response.status_code == 503
    assert response_json(response) == {
        "status": "unavailable",
        "checks": {"database": "unavailable"},
    }


def test_readiness_returns_503_when_redis_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database(monkeypatch)
    configure_settings(
        monkeypatch,
        async_campaigns=True,
        redis_url=None,
    )

    response = main.readiness_check()

    assert response.status_code == 503
    assert response_json(response) == {
        "status": "unavailable",
        "checks": {
            "database": "ok",
            "redis": "unavailable",
        },
    }


def test_readiness_returns_503_when_redis_ping_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database(monkeypatch)
    configure_settings(
        monkeypatch,
        async_campaigns=True,
        redis_url="redis://localhost:6379/0",
    )

    client = MagicMock()
    client.ping.side_effect = RedisError("Redis unavailable")
    monkeypatch.setattr(
        main.Redis,
        "from_url",
        MagicMock(return_value=client),
    )

    response = main.readiness_check()

    assert response.status_code == 503
    assert response_json(response) == {
        "status": "unavailable",
        "checks": {
            "database": "ok",
            "redis": "unavailable",
        },
    }
    client.close.assert_called_once()


def test_readiness_preserves_result_when_redis_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database(monkeypatch)
    configure_settings(
        monkeypatch,
        async_campaigns=True,
        redis_url="redis://localhost:6379/0",
    )

    client = MagicMock()
    client.ping.return_value = True
    client.close.side_effect = OSError("cleanup failed")
    monkeypatch.setattr(
        main.Redis,
        "from_url",
        MagicMock(return_value=client),
    )

    response = main.readiness_check()

    assert response.status_code == 200
    assert response_json(response) == {
        "status": "ok",
        "checks": {
            "database": "ok",
            "redis": "ok",
        },
    }
    client.close.assert_called_once()


def test_readiness_returns_200_when_database_and_redis_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database(monkeypatch)
    configure_settings(
        monkeypatch,
        async_campaigns=True,
        redis_url="redis://localhost:6379/0",
    )

    client = MagicMock()
    client.ping.return_value = True
    monkeypatch.setattr(
        main.Redis,
        "from_url",
        MagicMock(return_value=client),
    )

    response = main.readiness_check()

    assert response.status_code == 200
    assert response_json(response) == {
        "status": "ok",
        "checks": {
            "database": "ok",
            "redis": "ok",
        },
    }
    client.close.assert_called_once()
