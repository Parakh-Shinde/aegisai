
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.tool_evaluations import claim_promptfoo_run
from app.db.models import (
    AISystemProfileRecord,
    Base,
    Organization,
    ToolEvaluationRunRecord,
    ToolEvaluationTargetRecord,
)
from app.services.promptfoo_adapter import (
    build_promptfoo_config,
    config_digest,
)


def test_concurrent_claim_cannot_claim_the_same_pending_run() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    run_id = "run-claim-test"
    target_id = "target-claim-test"
    system_id = "system-claim-test"
    organization_id = "organization-claim-test"
    suite_name = "aegisai_local_safety_smoke"
    endpoint = "http://127.0.0.1:11434"
    model_name = "test-model"

    config = build_promptfoo_config(
        model_name,
        suite_name,
        provider="ollama",
        endpoint=endpoint,
    )

    try:
        with Session(engine, expire_on_commit=False) as setup_db:
            organization = Organization(
                id=organization_id,
                name="Claim Test Organization",
                slug="claim-test-organization",
            )
            system = AISystemProfileRecord(
                id=system_id,
                organization_id=organization_id,
                name="Claim Test System",
                system_type="llm",
                deployment_exposure="local",
                data_classification="internal",
            )
            target = ToolEvaluationTargetRecord(
                id=target_id,
                organization_id=organization_id,
                system_id=system_id,
                name="Claim Test Target",
                provider="ollama",
                endpoint=endpoint,
                model_name=model_name,
                authorization_confirmed=True,
                active=True,
            )
            run = ToolEvaluationRunRecord(
                id=run_id,
                organization_id=organization_id,
                system_id=system_id,
                target_id=target_id,
                tool_name="promptfoo",
                tool_version="test-version",
                suite_name=suite_name,
                config_digest=config_digest(config),
                status="pending",
                planned_tests=1,
                executed_tests=0,
                passed_tests=0,
                failed_tests=0,
                skipped_tests=0,
            )
            setup_db.add_all([organization, system, target, run])
            setup_db.commit()

        # Both workers read the pending run before either claims it.
        with (
            Session(engine, expire_on_commit=False) as worker_one,
            Session(engine, expire_on_commit=False) as worker_two,
        ):
            first_observation = worker_one.get(
                ToolEvaluationRunRecord, run_id
            )
            second_observation = worker_two.get(
                ToolEvaluationRunRecord, run_id
            )

            assert first_observation is not None
            assert second_observation is not None
            assert first_observation.status == "pending"
            assert second_observation.status == "pending"

            # The first worker successfully claims the run.
            response = claim_promptfoo_run(run_id, worker_one)
            assert response.run_id == run_id

            claimed_run = worker_one.scalar(
                select(ToolEvaluationRunRecord).where(
                    ToolEvaluationRunRecord.id == run_id
                )
            )
            assert claimed_run is not None
            assert claimed_run.status == "running"

            original_started_at = claimed_run.started_at
            assert original_started_at is not None

            # The second worker still has a stale "pending" ORM object.
            assert second_observation.status == "pending"

            # The conditional UPDATE must reject the stale claimant.
            try:
                claim_promptfoo_run(run_id, worker_two)
            except HTTPException as exc:
                assert exc.status_code == 409
                assert exc.detail == "Tool evaluation run is not pending."
            else:
                raise AssertionError(
                    "A duplicate claim unexpectedly succeeded."
                )

        # Verify persisted state using a fresh database session.
        with Session(engine) as verify_db:
            persisted_run = verify_db.get(
                ToolEvaluationRunRecord, run_id
            )
            assert persisted_run is not None
            assert persisted_run.status == "running"
            assert persisted_run.started_at is not None

            # SQLite may return a naive datetime even when the original
            # value was timezone-aware. Compare the same wall-clock value.
            persisted_started_at = persisted_run.started_at.replace(
                tzinfo=original_started_at.tzinfo
            )
            assert persisted_started_at == original_started_at

    finally:
        engine.dispose()
