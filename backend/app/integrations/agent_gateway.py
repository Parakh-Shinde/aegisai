"""Fail-closed client for enforcing AEGISAI decisions in an agent runtime."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar
from urllib.parse import urlparse
from uuid import uuid4

import httpx

Result = TypeVar("Result")


class AgentGatewayError(RuntimeError):
    """The gateway could not provide a trustworthy enforcement decision."""


class AgentActionDenied(AgentGatewayError):
    """The gateway denied or paused an action, so it must not execute."""


@dataclass(frozen=True)
class AgentActionProposal:
    action_type: str
    tool_name: str
    target: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    page_excerpt: str | None = None

    def as_payload(self, system_id: str) -> dict[str, Any]:
        if not all(
            value.strip()
            for value in (system_id, self.action_type, self.tool_name)
        ):
            raise ValueError("system_id, action_type, and tool_name must not be empty.")
        payload = {
            "system_id": system_id,
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "target": self.target,
            "arguments": self.arguments,
            "page_excerpt": self.page_excerpt,
        }
        try:
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Agent action proposal must be JSON serializable."
            ) from exc
        return payload


@dataclass(frozen=True)
class AgentGatewayDecision:
    decision: str
    execution_permitted: bool
    action_id: str
    idempotent_replay: bool


class AgentGatewayClient:
    """Ask AEGISAI for a decision before a runtime executes an action.

    The client is fail-closed: a network error, malformed response, or a
    `deny`/`require_review` decision raises an exception before `execute` calls
    the supplied operation. The calling agent must use `execute` (or check
    `authorize`) immediately before every protected tool call.
    """

    def __init__(
        self,
        *,
        gateway_base_url: str,
        system_id: str,
        token: str | None = None,
        timeout_seconds: float = 5.0,
        allow_insecure_http: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not system_id.strip():
            raise ValueError("system_id must not be empty.")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 1 and 30.")
        self._endpoint = _enforcement_endpoint(
            gateway_base_url,
            allow_insecure_http=allow_insecure_http,
        )
        self._system_id = system_id.strip()
        self._token = token
        self._client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            transport=transport,
        )

    @classmethod
    def from_environment(
        cls,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> AgentGatewayClient:
        gateway_base_url = os.getenv("AEGISAI_AGENT_GATEWAY_URL")
        system_id = os.getenv("AEGISAI_AGENT_SYSTEM_ID")
        if not gateway_base_url or not system_id:
            raise ValueError(
                "AEGISAI_AGENT_GATEWAY_URL and AEGISAI_AGENT_SYSTEM_ID are required."
            )
        return cls(
            gateway_base_url=gateway_base_url,
            system_id=system_id,
            token=os.getenv("AEGISAI_AGENT_GATEWAY_TOKEN") or None,
            timeout_seconds=float(os.getenv("AEGISAI_AGENT_GATEWAY_TIMEOUT", "5")),
            allow_insecure_http=(
                os.getenv("AEGISAI_AGENT_GATEWAY_ALLOW_INSECURE_HTTP", "false").lower()
                == "true"
            ),
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def authorize(
        self,
        proposal: AgentActionProposal,
        *,
        idempotency_key: str | None = None,
    ) -> AgentGatewayDecision:
        """Request a decision. It never invokes the proposed action itself."""
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key or str(uuid4()),
        }
        if self._token:
            headers["X-AEGISAI-Agent-Token"] = self._token
        try:
            response = self._client.post(
                self._endpoint,
                headers=headers,
                json=proposal.as_payload(self._system_id),
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentGatewayError(
                "AEGISAI gateway did not return a valid decision."
            ) from exc
        return _parse_decision(body)

    def execute(
        self,
        proposal: AgentActionProposal,
        operation: Callable[[], Result],
        *,
        idempotency_key: str | None = None,
    ) -> Result:
        """Execute only after an immediate, explicit allow decision."""
        decision = self.authorize(proposal, idempotency_key=idempotency_key)
        if not decision.execution_permitted or decision.decision != "allow":
            raise AgentActionDenied(
                f"AEGISAI prevented this agent action: {decision.decision}."
            )
        return operation()

    def __enter__(self) -> AgentGatewayClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _enforcement_endpoint(base_url: str, *, allow_insecure_http: bool) -> str:
    normalized = base_url.strip().rstrip("/")
    parsed = urlparse(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("gateway_base_url must be a plain absolute http(s) URL.")
    if parsed.scheme != "https" and not allow_insecure_http:
        raise ValueError(
            "HTTPS is required unless allow_insecure_http is explicitly enabled."
        )
    return f"{normalized}/agent-security/enforce"


def _parse_decision(value: object) -> AgentGatewayDecision:
    if not isinstance(value, dict):
        raise AgentGatewayError("AEGISAI gateway returned a malformed decision.")
    decision = value.get("decision")
    execution_permitted = value.get("execution_permitted")
    idempotent_replay = value.get("idempotent_replay", False)
    action = value.get("action")
    if (
        decision not in {"allow", "require_review", "deny"}
        or not isinstance(execution_permitted, bool)
        or not isinstance(idempotent_replay, bool)
        or not isinstance(action, dict)
        or not isinstance(action.get("id"), str)
    ):
        raise AgentGatewayError("AEGISAI gateway returned a malformed decision.")
    return AgentGatewayDecision(
        decision=decision,
        execution_permitted=execution_permitted,
        action_id=action["id"],
        idempotent_replay=idempotent_replay,
    )
