import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest

from app.api.ai_systems import (
    _apply_evidence_freshness,
    decide_release_approval,
    get_ai_system_release_decision,
    request_release_approval,
)
from app.core.auth import ACTOR_SESSION_KEY, Actor
from app.db.models import (
    AISystemProfileRecord,
    Base,
    Organization,
    SecurityTestResultRecord,
    ToolEvaluationRunRecord,
    ToolEvaluationTargetRecord,
    User,
    UserRole,
)
from app.models.ai_system import (
    ReleaseApprovalDecisionRequest,
    ReleaseApprovalRequest,
    SystemReleaseEvidenceResponse,
)
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def test_unified_release_decision_passes_only_with_linked_evidence() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)

    with Session(engine) as db:
        organization = Organization(id="org-1", name="Org", slug="org")
        user = User(
            id="user-1",
            organization_id=organization.id,
            email="analyst@example.com",
            password_hash="not-used",
            role=UserRole.SECURITY_ANALYST,
        )
        approver = User(
            id="user-2",
            organization_id=organization.id,
            email="admin@example.com",
            password_hash="not-used",
            role=UserRole.ADMIN,
        )
        system = AISystemProfileRecord(
            id="system-1",
            organization_id=organization.id,
            created_by_user_id=user.id,
            name="Test model API",
            system_type="model_api",
            deployment_exposure="internal",
            data_classification="internal",
            input_modalities=["text"],
            capabilities=[],
            created_at=now - timedelta(minutes=1),
            updated_at=now - timedelta(minutes=1),
        )
        target = ToolEvaluationTargetRecord(
            id="target-1",
            organization_id=organization.id,
            system_id=system.id,
            created_by_user_id=user.id,
            name="approved-target",
            provider="ollama",
            endpoint="http://ollama.test",
            model_name="test-model",
            authorization_confirmed=True,
            active=True,
        )
        run = ToolEvaluationRunRecord(
            id="run-1",
            organization_id=organization.id,
            system_id=system.id,
            target_id=target.id,
            created_by_user_id=user.id,
            tool_name="promptfoo",
            tool_version="test",
            suite_name="smoke",
            config_digest="a" * 64,
            status="completed",
            planned_tests=3,
            executed_tests=3,
            passed_tests=3,
            failed_tests=0,
            skipped_tests=0,
            completed_at=now,
        )
        results = [
            SecurityTestResultRecord(
                test_id=f"test-{index}",
                organization_id=organization.id,
                created_by_user_id=user.id,
                created_at=now,
                test_type="prompt_injection",
                test_category="prompt_injection",
                model="test-model",
                risk_status="blocked",
                severity="none",
                latency_ms=10,
                recommendation="No action required.",
                finding="Blocked safely.",
                prompt_sent="controlled prompt",
                model_response="safe response",
                review_status="unreviewed",
                triage_status="resolved",
            )
            for index in range(10)
        ]
        db.add_all([organization, user, approver, system, target, run, *results])
        db.commit()
        db.info[ACTOR_SESSION_KEY] = Actor(
            user_id=user.id,
            organization_id=organization.id,
            role=user.role,
            email=user.email,
        )

        decision = get_ai_system_release_decision(system.id, db)

        assert decision.decision == "pass"
        assert {item.source for item in decision.evidence} == {
            "model_target",
            "security_campaigns",
            "external_tool_evaluation",
            "file_security",
            "rag_security",
            "agent_runtime",
        }
        assert decision.evidence[1].status == "pass"
        assert decision.evidence[2].status == "pass"

        approval = request_release_approval(
            system.id,
            ReleaseApprovalRequest(request_notes="Ready for independent approval."),
            db,
        )
        assert approval.approval_status == "pending"
        assert approval.release_decision == "pass"
        assert len(approval.decision_digest) == 64

        db.info[ACTOR_SESSION_KEY] = Actor(
            user_id=approver.id,
            organization_id=organization.id,
            role=approver.role,
            email=approver.email,
        )
        with pytest.raises(HTTPException, match="Security Analyst"):
            request_release_approval(
                system.id,
                ReleaseApprovalRequest(
                    request_notes="An Admin cannot request final approval."
                ),
                db,
            )
        approved = decide_release_approval(
            system.id,
            approval.id,
            ReleaseApprovalDecisionRequest(
                outcome="approved",
                decision_notes="Independent evidence review completed.",
            ),
            db,
        )
        assert approved.approval_status == "approved"
        assert approved.decided_by_user_id == approver.id


def test_evidence_older_than_profile_or_policy_window_requires_retest() -> None:
    now = datetime.now(UTC)
    evidence = [
        SystemReleaseEvidenceResponse(
            source="external_tool_evaluation",
            status="pass",
            summary="Completed with zero failed tests.",
            evidence_count=1,
            evidence_ids=["run-1"],
            latest_evidence_at=now - timedelta(hours=2),
        )
    ]

    stale_sources = _apply_evidence_freshness(
        evidence,
        profile_updated_at=now - timedelta(hours=3),
        now=now,
        max_age_hours=1,
    )

    assert stale_sources == ["external_tool_evaluation"]
    assert evidence[0].status == "manual_review_required"
    assert evidence[0].retest_required
    assert "older than 1 hour" in evidence[0].summary


def test_release_gate_requires_complete_consistent_tool_results() -> None:
    from types import SimpleNamespace

    from app.api.ai_systems import _tool_run_has_complete_results

    complete = SimpleNamespace(
        planned_tests=12,
        executed_tests=12,
        skipped_tests=0,
        passed_tests=10,
        failed_tests=2,
    )
    partial = SimpleNamespace(
        planned_tests=12,
        executed_tests=10,
        skipped_tests=2,
        passed_tests=10,
        failed_tests=0,
    )
    inconsistent = SimpleNamespace(
        planned_tests=12,
        executed_tests=12,
        skipped_tests=0,
        passed_tests=11,
        failed_tests=0,
    )
    empty = SimpleNamespace(
        planned_tests=0,
        executed_tests=0,
        skipped_tests=0,
        passed_tests=0,
        failed_tests=0,
    )

    assert _tool_run_has_complete_results(complete)
    assert not _tool_run_has_complete_results(partial)
    assert not _tool_run_has_complete_results(inconsistent)
    assert not _tool_run_has_complete_results(empty)


def test_rag_release_gate_requires_an_explicitly_eligible_state() -> None:
    from types import SimpleNamespace

    from app.api.ai_systems import _rag_source_is_release_eligible

    auto_approved = SimpleNamespace(
        review_state="auto_approved", verdict="approved"
    )
    admin_exception = SimpleNamespace(
        review_state="approved_exception", verdict="quarantined"
    )
    pending = SimpleNamespace(review_state="pending_review", verdict="quarantined")
    rejected = SimpleNamespace(review_state="rejected", verdict="quarantined")
    inconsistent = SimpleNamespace(review_state="auto_approved", verdict="quarantined")
    unknown = SimpleNamespace(review_state="unknown_state", verdict="approved")

    assert _rag_source_is_release_eligible(auto_approved)
    assert _rag_source_is_release_eligible(admin_exception)
    assert not _rag_source_is_release_eligible(pending)
    assert not _rag_source_is_release_eligible(rejected)
    assert not _rag_source_is_release_eligible(inconsistent)
    assert not _rag_source_is_release_eligible(unknown)
