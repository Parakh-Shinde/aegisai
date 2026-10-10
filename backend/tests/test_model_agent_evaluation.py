import json

import httpx
import pytest
from app.services.model_agent_evaluation import (
    ModelAgentEvaluationError,
    load_model_agent_suite,
    rejected_model_output_analysis,
    request_model_action,
)


def test_model_agent_suite_is_versioned_and_has_expected_coverage() -> None:
    suite = load_model_agent_suite()

    assert suite.suite_name == "model_agent_gateway_adversarial_suite"
    assert suite.version == "1.0.0"
    assert len(suite.tests) == 6
    assert {test.expected_verdict for test in suite.tests} == {
        "allowed",
        "quarantined",
        "blocked",
    }


def test_model_action_request_parses_a_controlled_json_proposal() -> None:
    suite = load_model_agent_suite()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://ollama.test/api/chat"
        request_body = json.loads(request.content)
        assert request_body["model"] == "test-model"
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "action_type": "http_request",
                            "tool_name": "http_client",
                            "target": "http://127.0.0.1:8080/admin",
                            "arguments": {},
                            "page_excerpt": None,
                        }
                    )
                }
            },
        )

    proposal = request_model_action(
        endpoint="http://ollama.test",
        model_name="test-model",
        test=suite.tests[0],
        timeout_seconds=10,
        transport=httpx.MockTransport(handler),
    )

    assert proposal.action_type == "http_request"
    assert proposal.target == "http://127.0.0.1:8080/admin"


def test_invalid_model_action_fails_closed() -> None:
    suite = load_model_agent_suite()

    with pytest.raises(ModelAgentEvaluationError, match="action JSON"):
        request_model_action(
            endpoint="http://ollama.test",
            model_name="test-model",
            test=suite.tests[0],
            timeout_seconds=10,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json={"message": {"content": "nope"}})
            ),
        )

    analysis = rejected_model_output_analysis("invalid output")
    assert analysis.verdict == "blocked"
    assert analysis.signals[0].code == "model_action_output_rejected"
