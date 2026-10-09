import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api.security_tests import (  # noqa: E402
    CorpusProvenance,
    build_regression_gate_response,
    build_scorecard,
    campaign_evidence_fingerprint,
    load_corpus_suite,
    triage_due_at,
)
from app.db.models import EvaluationBaseline, SecurityTestResultRecord  # noqa: E402


def make_record(
    *,
    test_id: str,
    risk_status: str = "blocked",
    severity: str = "none",
) -> SecurityTestResultRecord:
    return SecurityTestResultRecord(
        test_id=test_id,
        organization_id="organization-1",
        created_by_user_id="user-1",
        created_at=datetime(2026, 10, 8, tzinfo=UTC),
        test_type="prompt_injection_basic",
        test_category="prompt_injection",
        model="candidate-model",
        risk_status=risk_status,
        severity=severity,
        latency_ms=10,
        recommendation="test recommendation",
        finding="test finding",
        prompt_sent="stored-prompt",
        model_response="stored-response",
        campaign_id="campaign-1",
        corpus_suite_name="basic_safety_suite",
        corpus_version="1.0.0",
        corpus_digest="a" * 64,
        scoring_rule_version="risk-markers-v1",
        review_status="confirmed_safe",
    )


def make_baseline() -> EvaluationBaseline:
    return EvaluationBaseline(
        id="baseline-1",
        organization_id="organization-1",
        created_by_user_id="user-1",
        name="approved-v1",
        source_campaign_id="campaign-baseline",
        model="baseline-model",
        corpus_suite_name="basic_safety_suite",
        corpus_version="1.0.0",
        corpus_digest="a" * 64,
        scoring_rule_version="risk-markers-v1",
        total_tests=10,
        safety_score=100,
        leaked_tests=0,
        uncertain_tests=0,
        high_risk_tests=0,
        evidence_fingerprint="b" * 64,
    )


def test_versioned_corpus_has_stable_metadata() -> None:
    corpus = load_corpus_suite("basic_safety_suite")

    assert corpus.suite_name == "basic_safety_suite"
    assert corpus.version == "1.0.0"
    assert corpus.scoring_rule_version == "risk-markers-v1"
    assert len(corpus.digest) == 64
    assert len(corpus.tests) == 10


def test_evidence_fingerprint_is_reproducible() -> None:
    record = make_record(test_id="test-1")

    assert campaign_evidence_fingerprint([record]) == campaign_evidence_fingerprint(
        [record]
    )


def test_regression_gate_fails_on_new_high_risk_finding() -> None:
    candidate_records = [
        make_record(test_id="test-1"),
        make_record(test_id="test-2", risk_status="leaked", severity="high"),
    ]
    response = build_regression_gate_response(
        campaign_id="campaign-1",
        baseline=make_baseline(),
        corpus=CorpusProvenance(
            suite_name="basic_safety_suite",
            version="1.0.0",
            digest="a" * 64,
            scoring_rule_version="risk-markers-v1",
        ),
        candidate_scorecard=build_scorecard(candidate_records, model="candidate-model"),
    )

    assert response.decision == "fail"
    assert response.leaked_test_delta == 1
    assert response.high_risk_test_delta == 1


def test_regression_gate_requires_review_for_different_corpus() -> None:
    response = build_regression_gate_response(
        campaign_id="campaign-1",
        baseline=make_baseline(),
        corpus=CorpusProvenance(
            suite_name="basic_safety_suite",
            version="2.0.0",
            digest="c" * 64,
            scoring_rule_version="risk-markers-v2",
        ),
        candidate_scorecard=build_scorecard(
            [make_record(test_id="test-1")],
            model="candidate-model",
        ),
    )

    assert response.decision == "manual_review_required"
    assert "different corpus" in response.reason.lower()


def test_finding_sla_deadlines_match_severity() -> None:
    now = datetime(2026, 10, 9, tzinfo=UTC)

    assert triage_due_at("high", now) == now + timedelta(hours=24)
    assert triage_due_at("medium", now) == now + timedelta(hours=72)
    assert triage_due_at("none", now) == now + timedelta(days=7)
