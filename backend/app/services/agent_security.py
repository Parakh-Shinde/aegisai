import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

from app.services.rag_security import analyze_rag_source

SECRET_FIELD_PATTERN = re.compile(
    r"(?:api[_-]?key|password|secret|token|credential|authorization)",
    re.IGNORECASE,
)
DESTRUCTIVE_ACTION_PATTERN = re.compile(
    r"(?:delete|drop|wipe|destroy|disable|revoke)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AgentSecuritySignal:
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


@dataclass(frozen=True)
class AgentActionAnalysis:
    request_sha256: str
    request_characters: int
    verdict: Literal["allowed", "quarantined", "blocked"]
    signals: list[AgentSecuritySignal]
    recommendation: str


def analyze_agent_action(
    *,
    action_type: str,
    tool_name: str,
    target: str | None,
    arguments: dict[str, Any],
    page_excerpt: str | None,
) -> AgentActionAnalysis:
    """Perform non-executing checks against a proposed agent action.

    This function never invokes the tool, opens a URL, resolves DNS, accesses a
    connector, or sends a browser request. It only evaluates caller-provided
    metadata and page text in order to support a policy decision.
    """
    normalized_request = json.dumps(
        {
            "action_type": action_type,
            "tool_name": tool_name,
            "target": target,
            "arguments": arguments,
            "page_excerpt": page_excerpt,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    signals: list[AgentSecuritySignal] = []
    normalized_target = (target or "").strip()
    serialized_arguments = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    if action_type == "shell_command":
        signals.append(
            AgentSecuritySignal(
                code="shell_execution_blocked",
                severity="high",
                message=(
                    "Shell-command actions are blocked outside a dedicated "
                    "sandbox."
                ),
            )
        )
    if action_type in {"browser_navigation", "http_request"}:
        signals.extend(_network_target_signals(normalized_target))
    if action_type == "file_operation":
        signals.extend(_file_target_signals(normalized_target))
    if action_type == "data_export":
        signals.append(
            AgentSecuritySignal(
                code="data_export_requires_review",
                severity="high",
                message="Data export requires an explicit human review decision.",
            )
        )
    destructive_tool_name = DESTRUCTIVE_ACTION_PATTERN.search(tool_name)
    destructive_arguments = DESTRUCTIVE_ACTION_PATTERN.search(serialized_arguments)
    if destructive_tool_name or destructive_arguments:
        signals.append(
            AgentSecuritySignal(
                code="destructive_action_marker",
                severity="high",
                message="Proposed tool action includes a destructive-operation marker.",
            )
        )
    if SECRET_FIELD_PATTERN.search(serialized_arguments):
        signals.append(
            AgentSecuritySignal(
                code="sensitive_argument_marker",
                severity="medium",
                message=(
                    "Proposed action arguments contain a secret or credential field "
                    "name."
                ),
            )
        )
    if page_excerpt:
        source_analysis = analyze_rag_source(page_excerpt)
        signals.extend(
            AgentSecuritySignal(
                code=f"browser_{signal.code}",
                severity=signal.severity,
                message=signal.message,
            )
            for signal in source_analysis.signals
        )

    verdict = _verdict_for_signals(signals)
    return AgentActionAnalysis(
        request_sha256=hashlib.sha256(normalized_request.encode("utf-8")).hexdigest(),
        request_characters=len(normalized_request),
        verdict=verdict,
        signals=signals,
        recommendation=_recommendation_for_verdict(verdict),
    )


def _network_target_signals(target: str) -> list[AgentSecuritySignal]:
    parsed = urlparse(target)
    if not target or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return [
            AgentSecuritySignal(
                code="invalid_network_target",
                severity="high",
                message=(
                    "Browser or HTTP actions require a complete http(s) target "
                    "URL."
                ),
            )
        ]
    if parsed.username or parsed.password:
        return [
            AgentSecuritySignal(
                code="credentialed_url_blocked",
                severity="high",
                message="URLs containing credentials are blocked.",
            )
        ]
    hostname = parsed.hostname.lower()
    internal_host_suffixes = (".localhost", ".local", ".internal")
    internal_hostnames = {
        "localhost",
        "host.docker.internal",
        "metadata.google.internal",
    }
    if hostname in internal_hostnames or hostname.endswith(internal_host_suffixes):
        return [
            AgentSecuritySignal(
                code="internal_network_target",
                severity="high",
                message="Local or internal network targets are blocked.",
            )
        ]
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return [
            AgentSecuritySignal(
                code="internal_network_target",
                severity="high",
                message="Private, loopback, or reserved IP targets are blocked.",
            )
        ]
    if parsed.query:
        return [
            AgentSecuritySignal(
                code="network_query_requires_review",
                severity="medium",
                message="Network target includes query data and requires review.",
            )
        ]
    return []


def _file_target_signals(target: str) -> list[AgentSecuritySignal]:
    if not target:
        return [
            AgentSecuritySignal(
                code="missing_file_target",
                severity="high",
                message="File operations require an explicit relative target path.",
            )
        ]
    normalized = target.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/"):
        return [
            AgentSecuritySignal(
                code="file_path_escape",
                severity="high",
                message="Absolute paths and path traversal are blocked.",
            )
        ]
    return []


def _verdict_for_signals(
    signals: list[AgentSecuritySignal],
) -> Literal["allowed", "quarantined", "blocked"]:
    blocking_codes = {
        "shell_execution_blocked",
        "invalid_network_target",
        "credentialed_url_blocked",
        "internal_network_target",
        "missing_file_target",
        "file_path_escape",
    }
    if any(signal.code in blocking_codes for signal in signals):
        return "blocked"
    if any(signal.severity in {"medium", "high"} for signal in signals):
        return "quarantined"
    return "allowed"


def _recommendation_for_verdict(
    verdict: Literal["allowed", "quarantined", "blocked"],
) -> str:
    if verdict == "allowed":
        return (
            "Static policy checks passed. Execute only in the target agent's "
            "approved runtime."
        )
    if verdict == "quarantined":
        return (
            "Do not execute this action until an authorized reviewer records a "
            "decision."
        )
    return "Reject this action. Use a sandboxed runtime and an approved target instead."
