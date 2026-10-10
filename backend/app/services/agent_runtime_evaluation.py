"""Versioned, non-executing agent-runtime evaluation assets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.services.agent_security import AgentActionAnalysis, analyze_agent_action

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
SUPPORTED_SUITE = "agent_runtime_adversarial_suite"
Verdict = Literal["allowed", "quarantined", "blocked"]


class AgentRuntimeEvaluationAssetError(RuntimeError):
    """Raised when a committed evaluation asset is invalid or unavailable."""


@dataclass(frozen=True)
class AgentRuntimeEvaluationCase:
    test_id: str
    action_type: str
    tool_name: str
    target: str | None
    arguments: dict[str, Any]
    page_excerpt: str | None
    expected_verdict: Verdict


@dataclass(frozen=True)
class AgentRuntimeEvaluationSuite:
    suite_name: str
    version: str
    scoring_rule_version: str
    digest: str
    tests: list[AgentRuntimeEvaluationCase]


def load_agent_runtime_suite() -> AgentRuntimeEvaluationSuite:
    """Load the single approved local test suite without contacting a model."""
    path = CORPUS_DIR / f"{SUPPORTED_SUITE}.json"
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentRuntimeEvaluationAssetError(
            "Unable to load the committed agent runtime evaluation suite."
        ) from exc
    if not isinstance(data, dict) or data.get("suite_name") != SUPPORTED_SUITE:
        raise AgentRuntimeEvaluationAssetError(
            "Invalid agent runtime evaluation suite."
        )
    version = data.get("version")
    scoring_rule_version = data.get("scoring_rule_version")
    tests = data.get("tests")
    if not isinstance(version, str) or not isinstance(scoring_rule_version, str):
        raise AgentRuntimeEvaluationAssetError("Suite provenance is incomplete.")
    if not isinstance(tests, list) or not tests:
        raise AgentRuntimeEvaluationAssetError("Suite must contain at least one test.")

    parsed_tests = [_parse_test(test) for test in tests]
    test_ids = [test.test_id for test in parsed_tests]
    if len(test_ids) != len(set(test_ids)):
        raise AgentRuntimeEvaluationAssetError("Suite contains duplicate test IDs.")
    return AgentRuntimeEvaluationSuite(
        suite_name=SUPPORTED_SUITE,
        version=version,
        scoring_rule_version=scoring_rule_version,
        digest=hashlib.sha256(raw).hexdigest(),
        tests=parsed_tests,
    )


def evaluate_agent_runtime_case(
    test: AgentRuntimeEvaluationCase,
) -> AgentActionAnalysis:
    """Evaluate static test data; this function never executes the proposed action."""
    return analyze_agent_action(
        action_type=test.action_type,
        tool_name=test.tool_name,
        target=test.target,
        arguments=test.arguments,
        page_excerpt=test.page_excerpt,
    )


def _parse_test(value: object) -> AgentRuntimeEvaluationCase:
    if not isinstance(value, dict):
        raise AgentRuntimeEvaluationAssetError("Suite test must be a JSON object.")
    required_strings = ("test_id", "action_type", "tool_name")
    if any(
        not isinstance(value.get(key), str) or not value[key]
        for key in required_strings
    ):
        raise AgentRuntimeEvaluationAssetError("Suite test metadata is incomplete.")
    expected_verdict = value.get("expected_verdict")
    if expected_verdict not in {"allowed", "quarantined", "blocked"}:
        raise AgentRuntimeEvaluationAssetError(
            "Suite test has an invalid expected verdict."
        )
    target = value.get("target")
    page_excerpt = value.get("page_excerpt")
    arguments = value.get("arguments")
    if target is not None and not isinstance(target, str):
        raise AgentRuntimeEvaluationAssetError("Suite test target is invalid.")
    if page_excerpt is not None and not isinstance(page_excerpt, str):
        raise AgentRuntimeEvaluationAssetError("Suite test excerpt is invalid.")
    if not isinstance(arguments, dict):
        raise AgentRuntimeEvaluationAssetError("Suite test arguments are invalid.")
    return AgentRuntimeEvaluationCase(
        test_id=value["test_id"],
        action_type=value["action_type"],
        tool_name=value["tool_name"],
        target=target,
        arguments=arguments,
        page_excerpt=page_excerpt,
        expected_verdict=expected_verdict,
    )
