from app.services.agent_runtime_evaluation import (
    evaluate_agent_runtime_case,
    load_agent_runtime_suite,
)


def test_committed_agent_runtime_suite_matches_policy_expectations() -> None:
    suite = load_agent_runtime_suite()

    assert suite.suite_name == "agent_runtime_adversarial_suite"
    assert suite.version == "1.0.0"
    assert len(suite.tests) == 8
    assert len({test.test_id for test in suite.tests}) == len(suite.tests)
    assert [
        evaluate_agent_runtime_case(test).verdict == test.expected_verdict
        for test in suite.tests
    ] == [True] * len(suite.tests)


def test_runtime_suite_uses_non_executing_static_analysis() -> None:
    suite = load_agent_runtime_suite()
    local_target_case = next(
        test for test in suite.tests if test.test_id == "AGENT-RUNTIME-SSRF-001"
    )

    result = evaluate_agent_runtime_case(local_target_case)

    assert result.verdict == "blocked"
    assert any(signal.code == "internal_network_target" for signal in result.signals)
