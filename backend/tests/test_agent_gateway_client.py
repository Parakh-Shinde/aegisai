import json

import httpx
import pytest
from app.integrations.agent_gateway import (
    AgentActionDenied,
    AgentActionProposal,
    AgentGatewayClient,
    AgentGatewayError,
)


def test_execute_calls_operation_only_after_allow() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://aegis.example/agent-security/enforce"
        assert request.headers["x-aegisai-agent-token"] == "test-token"
        assert request.headers["idempotency-key"] == "safe-action-001"
        assert json.loads(request.content)["system_id"] == "agent-system-id"
        return httpx.Response(
            201,
            json={
                "decision": "allow",
                "execution_permitted": True,
                "idempotent_replay": False,
                "action": {"id": "action-001"},
            },
        )

    with AgentGatewayClient(
        gateway_base_url="https://aegis.example",
        system_id="agent-system-id",
        token="test-token",
        transport=httpx.MockTransport(handler),
    ) as gateway:
        result = gateway.execute(
            AgentActionProposal(
                action_type="browser_navigation",
                tool_name="knowledge_browser",
                target="https://docs.example.com/help",
            ),
            lambda: "operation ran",
            idempotency_key="safe-action-001",
        )

    assert result == "operation ran"


def test_execute_fails_closed_for_a_denied_action() -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={
                "decision": "deny",
                "execution_permitted": False,
                "idempotent_replay": False,
                "action": {"id": "action-002"},
            },
        )

    def operation() -> None:
        nonlocal called
        called = True

    with AgentGatewayClient(
        gateway_base_url="https://aegis.example",
        system_id="agent-system-id",
        transport=httpx.MockTransport(handler),
    ) as gateway:
        with pytest.raises(AgentActionDenied, match="prevented"):
            gateway.execute(
                AgentActionProposal(
                    action_type="shell_command",
                    tool_name="shell",
                ),
                operation,
            )

    assert not called


def test_client_requires_https_unless_development_http_is_explicit() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        AgentGatewayClient(
            gateway_base_url="http://127.0.0.1:8000",
            system_id="agent-system-id",
        )

    client = AgentGatewayClient(
        gateway_base_url="http://127.0.0.1:8000",
        system_id="agent-system-id",
        allow_insecure_http=True,
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )
    client.close()


def test_malformed_gateway_response_fails_closed() -> None:
    with AgentGatewayClient(
        gateway_base_url="https://aegis.example",
        system_id="agent-system-id",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json={})),
    ) as gateway:
        with pytest.raises(AgentGatewayError, match="malformed"):
            gateway.authorize(
                AgentActionProposal(
                    action_type="browser_navigation",
                    tool_name="knowledge_browser",
                    target="https://docs.example.com/help",
                )
            )
