import pytest
from app.models.tool_evaluations import ToolTargetRequest
from app.services.promptfoo_adapter import (
    PROMPTFOO_AI_SECURITY_BASELINE_SUITE_NAME,
    build_promptfoo_config,
    case_metadata,
    config_digest,
    parse_promptfoo_report,
)


def test_promptfoo_config_is_fixed_local_only_suite() -> None:
    config = build_promptfoo_config("llama3.2")

    assert config["providers"] == [{"id": "ollama:chat:llama3.2"}]
    assert config["sharing"] is False
    assert config["evaluateOptions"]["maxConcurrency"] == 1
    assert len(config["tests"]) == 3
    assert len(config_digest(config)) == 64


def test_ai_security_baseline_is_versioned_and_has_coverage_context() -> None:
    config = build_promptfoo_config(
        "llama3.2", PROMPTFOO_AI_SECURITY_BASELINE_SUITE_NAME
    )

    assert len(config["tests"]) == 12
    assert config["tests"][1]["metadata"]["aegisai_category"] == "prompt_injection"
    assert (
        case_metadata(
            PROMPTFOO_AI_SECURITY_BASELINE_SUITE_NAME, "AEGISAI-BASE-AGENT-002"
        )["expected_behavior"]
        == "block_untrusted_network_targets"
    )


def test_openai_compatible_target_config_uses_approved_endpoint() -> None:
    config = build_promptfoo_config(
        "my-assistant",
        PROMPTFOO_AI_SECURITY_BASELINE_SUITE_NAME,
        provider="openai_compatible",
        endpoint="https://staging.example.com/v1",
    )

    assert config["providers"] == [
        {
            "id": "openai:chat:my-assistant",
            "config": {"apiBaseUrl": "https://staging.example.com/v1"},
        }
    ]


def test_openai_compatible_target_requires_endpoint() -> None:
    with pytest.raises(ValueError, match="require an endpoint"):
        build_promptfoo_config(
            "my-assistant",
            provider="openai_compatible",
        )


def test_promptfoo_report_parser_normalizes_evidence() -> None:
    report = {
        "results": {
            "results": [
                {
                    "success": True,
                    "prompt": "safe prompt",
                    "response": {"output": "safe response"},
                    "metadata": {"aegisai_case_id": "AEGISAI-PF-SAFE-001"},
                    "gradingResult": {"score": 1, "componentResults": [{"pass": True}]},
                },
                {
                    "success": False,
                    "testCase": {
                        "vars": {"input": "second prompt"},
                        "metadata": {"aegisai_case_id": "AEGISAI-PF-PI-001"},
                    },
                    "response": {"output": "second response"},
                    "gradingResult": {"score": 0},
                },
            ]
        }
    }

    cases = parse_promptfoo_report(report)

    assert [case.outcome for case in cases] == ["passed", "failed"]
    assert cases[0].external_case_id == "AEGISAI-PF-SAFE-001"
    assert cases[1].prompt == "second prompt"
    assert cases[1].score == 0.0


def test_promptfoo_target_reuses_model_endpoint_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISAI_ALLOW_REMOTE_OLLAMA", raising=False)

    with pytest.raises(ValueError, match="remote endpoints"):
        ToolTargetRequest(
            system_id="system-1",
            name="not-authorized",
            endpoint="https://example.com",
            model_name="example-model",
            authorization_confirmed=True,
        )


def test_live_application_target_requires_exact_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISAI_LOCAL_APPLICATION_ENDPOINTS", raising=False)
    monkeypatch.delenv("AEGISAI_ALLOW_REMOTE_APPLICATION_TARGETS", raising=False)

    with pytest.raises(ValueError, match="remote endpoints"):
        ToolTargetRequest(
            system_id="system-1",
            name="not-authorized-live-app",
            provider="openai_compatible",
            endpoint="https://staging.example.com/v1",
            model_name="my-assistant",
            authorization_confirmed=True,
        )


def test_live_application_target_accepts_exact_local_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "http://host.docker.internal:9000/v1"
    monkeypatch.setenv("AEGISAI_LOCAL_APPLICATION_ENDPOINTS", endpoint)

    target = ToolTargetRequest(
        system_id="system-1",
        name="approved-live-app",
        provider="openai_compatible",
        endpoint=endpoint,
        model_name="my-assistant",
        authorization_confirmed=True,
    )

    assert target.endpoint == endpoint
