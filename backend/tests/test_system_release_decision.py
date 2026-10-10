import os
from datetime import UTC, datetime

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api.ai_systems import get_ai_system_release_decision  # noqa: E402
from app.core.auth import ACTOR_SESSION_KEY, Actor  # noqa: E402
from app.db.models import (  # noqa: E402
    AISystemProfileRecord,
    Base,
    Organization,
    SecurityTestResultRecord,
    ToolEvaluationRunRecord,
    ToolEvaluationTargetRecord,
    User,
    UserRole,
)
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402


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
        db.add_all([organization, user, system, target, run, *results])
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
