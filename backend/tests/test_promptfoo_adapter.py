import pytest
from app.models.tool_evaluations import ToolTargetRequest
from app.services.promptfoo_adapter import (
    build_promptfoo_config,
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

    with pytest.raises(ValueError, match="remote model endpoints"):
        ToolTargetRequest(
            system_id="system-1",
            name="not-authorized",
            endpoint="https://example.com",
            model_name="example-model",
            authorization_confirmed=True,
        )
