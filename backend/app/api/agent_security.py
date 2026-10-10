import json
from datetime import UTC, datetime
from time import perf_counter
from typing import Annotated, Literal, cast
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.evidence import protect_evidence, reveal_evidence
from app.core.security import (
    require_agent_gateway_token,
    require_api_key,
    validate_identifier,
)
from app.db.models import (
    AgentActionRecord,
    AgentRuntimeAssessmentRecord,
    AISystemProfileRecord,
    ToolEvaluationTargetRecord,
    UserRole,
)
from app.models.agent_security import (
    ActionReviewState,
    ActionType,
    AgentActionInspectionRequest,
    AgentActionResponse,
    AgentActionReviewRequest,
    AgentActionSummary,
    AgentEnforcementResponse,
    AgentRuntimeEvaluationCaseResponse,
    AgentRuntimeEvaluationRequest,
    AgentRuntimeEvaluationResponse,
    AgentRuntimeMetricsResponse,
    AgentSecuritySignalResponse,
    ModelAgentRuntimeEvaluationRequest,
)
from app.services.agent_runtime_evaluation import (
    AgentRuntimeEvaluationAssetError,
    evaluate_agent_runtime_case,
    load_agent_runtime_suite,
)
from app.services.agent_security import analyze_agent_action
from app.services.assessment_metrics import (
    AssessmentMetrics,
    GroundTruthCase,
    calculate_assessment_metrics,
)
from app.services.audit import write_audit_log
from app.services.model_agent_evaluation import (
    ModelAgentEvaluationError,
    load_model_agent_suite,
    rejected_model_output_analysis,
    request_model_action,
)

router = APIRouter(
    prefix="/agent-security",
    tags=["Agent Security"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
enforcement_router = APIRouter(
    prefix="/agent-security",
    tags=["Agent Security Enforcement"],
    dependencies=[Depends(require_agent_gateway_token)],
)
DBSession = Annotated[Session, Depends(get_db)]


def tenant_actions_query(db: Session) -> Select[AgentActionRecord]:
    return select(AgentActionRecord).where(
        AgentActionRecord.organization_id == request_actor(db).organization_id
    )


def require_tenant_agent_system(db: Session, system_id: str) -> AISystemProfileRecord:
    actor = request_actor(db)
    record = db.scalar(
        select(AISystemProfileRecord).where(
            AISystemProfileRecord.id == system_id,
            AISystemProfileRecord.organization_id == actor.organization_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    if not set(record.capabilities).intersection(
        {"agent_tools", "browser", "external_apis", "code_execution"}
    ):
        raise HTTPException(
            status_code=409,
            detail="Agent action inspection requires an agent-capable AI system.",
        )
    return record


def require_agent_system(db: Session, system_id: str) -> AISystemProfileRecord:
    record = db.get(AISystemProfileRecord, system_id)
    if record is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    if not set(record.capabilities).intersection(
        {"agent_tools", "browser", "external_apis", "code_execution"}
    ):
        raise HTTPException(
            status_code=409,
            detail="Agent action enforcement requires an agent-capable AI system.",
        )
    return record


def action_to_response(record: AgentActionRecord) -> AgentActionResponse:
    return AgentActionResponse(
        id=record.id,
        system_id=record.system_id,
        action_type=cast(ActionType, record.action_type),
        tool_name=record.tool_name,
        target=record.target,
        request_sha256=record.request_sha256,
        request_characters=record.request_characters,
        verdict=cast(Literal["allowed", "quarantined", "blocked"], record.verdict),
        signals=[
            AgentSecuritySignalResponse(
                code=signal["code"],
                severity=cast(Literal["low", "medium", "high"], signal["severity"]),
                message=signal["message"],
            )
            for signal in record.signals
        ],
        recommendation=record.recommendation,
        review_state=cast(ActionReviewState, record.review_state),
        review_notes=record.review_notes,
        reviewed_at=record.reviewed_at,
        created_at=record.created_at,
    )


@router.post(
    "/actions/inspect",
    response_model=AgentActionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def inspect_agent_action(
    request: AgentActionInspectionRequest,
    db: DBSession,
) -> AgentActionResponse:
    settings = get_settings()
    serialized_request = json.dumps(
        request.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(serialized_request) > settings.max_agent_action_characters:
        raise HTTPException(
            status_code=413,
            detail="Action inspection request exceeds the configured character limit.",
        )
    validate_identifier(request.system_id, "system_id")
    require_tenant_agent_system(db, request.system_id)
    analysis = analyze_agent_action(
        action_type=request.action_type,
        tool_name=request.tool_name,
        target=request.target,
        arguments=request.arguments,
        page_excerpt=request.page_excerpt,
    )
    actor = request_actor(db)
    review_state = _review_state_for_verdict(analysis.verdict)
    record = AgentActionRecord(
        organization_id=actor.organization_id,
        system_id=request.system_id,
        created_by_user_id=actor.user_id,
        action_type=request.action_type,
        tool_name=request.tool_name,
        target=request.target,
        decision_source="inspection",
        request_sha256=analysis.request_sha256,
        request_characters=analysis.request_characters,
        verdict=analysis.verdict,
        signals=[
            {
                "code": signal.code,
                "severity": signal.severity,
                "message": signal.message,
            }
            for signal in analysis.signals
        ],
        recommendation=analysis.recommendation,
        review_state=review_state,
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="agent_action.inspect",
        resource_type="agent_action_inspection",
        resource_id=record.id,
        details={
            "system_id": record.system_id,
            "action_type": record.action_type,
            "verdict": record.verdict,
            "signal_count": len(analysis.signals),
        },
    )
    db.commit()
    db.refresh(record)
    return action_to_response(record)


@enforcement_router.post(
    "/enforce",
    response_model=AgentEnforcementResponse,
    status_code=status.HTTP_201_CREATED,
)
def enforce_agent_action(
    request: AgentActionInspectionRequest,
    db: DBSession,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> AgentEnforcementResponse:
    settings = get_settings()
    serialized_request = json.dumps(
        request.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(serialized_request) > settings.max_agent_action_characters:
        raise HTTPException(
            status_code=413,
            detail="Action enforcement request exceeds the configured character limit.",
        )
    validate_identifier(request.system_id, "system_id")
    if idempotency_key is not None:
        validate_identifier(idempotency_key, "Idempotency-Key")
    system = require_agent_system(db, request.system_id)
    analysis = analyze_agent_action(
        action_type=request.action_type,
        tool_name=request.tool_name,
        target=request.target,
        arguments=request.arguments,
        page_excerpt=request.page_excerpt,
    )
    if idempotency_key is not None:
        existing = db.scalar(
            select(AgentActionRecord).where(
                AgentActionRecord.organization_id == system.organization_id,
                AgentActionRecord.system_id == system.id,
                AgentActionRecord.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.request_sha256 != analysis.request_sha256:
                raise HTTPException(
                    status_code=409,
                    detail="Idempotency-Key was already used for a different action.",
                )
            return _enforcement_response(
                existing,
                settings.agent_enforcement_mode,
                idempotent_replay=True,
            )

    record = AgentActionRecord(
        organization_id=system.organization_id,
        system_id=system.id,
        created_by_user_id=None,
        action_type=request.action_type,
        tool_name=request.tool_name,
        target=request.target,
        decision_source="enforcement",
        idempotency_key=idempotency_key,
        request_sha256=analysis.request_sha256,
        request_characters=analysis.request_characters,
        verdict=analysis.verdict,
        signals=[
            {
                "code": signal.code,
                "severity": signal.severity,
                "message": signal.message,
            }
            for signal in analysis.signals
        ],
        recommendation=analysis.recommendation,
        review_state=_review_state_for_verdict(analysis.verdict),
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=system.organization_id,
        actor_id=None,
        action="agent_action.enforce",
        resource_type="agent_action_inspection",
        resource_id=record.id,
        details={
            "system_id": record.system_id,
            "action_type": record.action_type,
            "verdict": record.verdict,
            "enforcement_mode": settings.agent_enforcement_mode,
        },
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if idempotency_key is None:
            raise
        existing = db.scalar(
            select(AgentActionRecord).where(
                AgentActionRecord.organization_id == system.organization_id,
                AgentActionRecord.system_id == system.id,
                AgentActionRecord.idempotency_key == idempotency_key,
            )
        )
        if existing is None:
            raise
        if existing.request_sha256 != analysis.request_sha256:
            raise HTTPException(
                status_code=409,
                detail="Idempotency-Key was already used for a different action.",
            ) from None
        return _enforcement_response(
            existing,
            settings.agent_enforcement_mode,
            idempotent_replay=True,
        )
    db.refresh(record)
    return _enforcement_response(record, settings.agent_enforcement_mode)


@router.post(
    "/evaluations/run",
    response_model=AgentRuntimeEvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def run_agent_runtime_evaluation(
    request: AgentRuntimeEvaluationRequest,
    db: DBSession,
) -> AgentRuntimeEvaluationResponse:
    """Run the committed static suite without executing any proposed action."""
    validate_identifier(request.system_id, "system_id")
    system = require_tenant_agent_system(db, request.system_id)
    try:
        suite = load_agent_runtime_suite()
    except AgentRuntimeEvaluationAssetError as exc:
        raise HTTPException(
            status_code=500,
            detail="The committed agent runtime evaluation suite is unavailable.",
        ) from exc

    actor = request_actor(db)
    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    assessment_started = perf_counter()
    case_responses: list[AgentRuntimeEvaluationCaseResponse] = []
    ground_truth_cases: list[GroundTruthCase] = []
    for test in suite.tests:
        case_started = perf_counter()
        analysis = evaluate_agent_runtime_case(test)
        case_elapsed_ms = round((perf_counter() - case_started) * 1000)
        ground_truth_cases.append(
            GroundTruthCase(
                expected_verdict=test.expected_verdict,
                actual_verdict=analysis.verdict,
                elapsed_ms=case_elapsed_ms,
            )
        )
        record = AgentActionRecord(
            organization_id=actor.organization_id,
            system_id=system.id,
            created_by_user_id=actor.user_id,
            action_type=test.action_type,
            tool_name=test.tool_name,
            target=test.target,
            decision_source="runtime_evaluation",
            evaluation_run_id=run_id,
            evaluation_case_id=test.test_id,
            evaluation_expected_verdict=test.expected_verdict,
            request_sha256=analysis.request_sha256,
            request_characters=analysis.request_characters,
            verdict=analysis.verdict,
            signals=[
                {
                    "code": signal.code,
                    "severity": signal.severity,
                    "message": signal.message,
                }
                for signal in analysis.signals
            ],
            recommendation=analysis.recommendation,
            review_state=_review_state_for_verdict(analysis.verdict),
        )
        db.add(record)
        db.flush()
        case_responses.append(
            AgentRuntimeEvaluationCaseResponse(
                test_id=test.test_id,
                action_id=record.id,
                expected_verdict=test.expected_verdict,
                actual_verdict=analysis.verdict,
                passed=analysis.verdict == test.expected_verdict,
                signals=[
                    AgentSecuritySignalResponse(
                        code=signal.code,
                        severity=signal.severity,
                        message=signal.message,
                    )
                    for signal in analysis.signals
                ],
            )
        )
    failed_tests = sum(not case.passed for case in case_responses)
    completed_at = datetime.now(UTC)
    metrics = calculate_assessment_metrics(
        ground_truth_cases,
        planned_tests=len(suite.tests),
        assessment_duration_ms=round((perf_counter() - assessment_started) * 1000),
    )
    assessment = AgentRuntimeAssessmentRecord(
        id=run_id,
        organization_id=actor.organization_id,
        system_id=system.id,
        created_by_user_id=actor.user_id,
        suite_name=suite.suite_name,
        corpus_version=suite.version,
        corpus_digest=suite.digest,
        scoring_rule_version=suite.scoring_rule_version,
        planned_tests=metrics.planned_tests,
        executed_tests=metrics.executed_tests,
        skipped_tests=metrics.skipped_tests,
        unsupported_tests=metrics.unsupported_tests,
        metrics=metrics.as_dict(),
        started_at=started_at,
        completed_at=completed_at,
    )
    db.add(assessment)
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="agent_runtime_evaluation.run",
        resource_type="agent_runtime_evaluation",
        resource_id=run_id,
        details={
            "system_id": system.id,
            "suite_name": suite.suite_name,
            "corpus_version": suite.version,
            "corpus_digest": suite.digest,
            "total_tests": len(case_responses),
            "failed_tests": failed_tests,
            "executed_tests": metrics.executed_tests,
        },
    )
    db.commit()
    return AgentRuntimeEvaluationResponse(
        run_id=run_id,
        system_id=system.id,
        suite_name=suite.suite_name,
        corpus_version=suite.version,
        corpus_digest=suite.digest,
        scoring_rule_version=suite.scoring_rule_version,
        total_tests=len(case_responses),
        passed_tests=len(case_responses) - failed_tests,
        failed_tests=failed_tests,
        evaluation_status="failed" if failed_tests else "passed",
        metrics=_metrics_to_response(metrics),
        cases=case_responses,
    )


@router.post(
    "/evaluations/model-run",
    response_model=AgentRuntimeEvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def run_model_agent_runtime_evaluation(
    request: ModelAgentRuntimeEvaluationRequest,
    db: DBSession,
) -> AgentRuntimeEvaluationResponse:
    """Send controlled scenarios to an approved model, then enforce proposals.

    This endpoint never performs the requested browser, shell, file, export, or
    network action. It only asks the model for a JSON proposal and evaluates it
    using the same gateway policy engine that protects a real agent runtime.
    """
    validate_identifier(request.system_id, "system_id")
    validate_identifier(request.target_id, "target_id")
    system = require_tenant_agent_system(db, request.system_id)
    actor = request_actor(db)
    target = db.scalar(
        select(ToolEvaluationTargetRecord).where(
            ToolEvaluationTargetRecord.id == request.target_id,
            ToolEvaluationTargetRecord.organization_id == actor.organization_id,
            ToolEvaluationTargetRecord.system_id == system.id,
        )
    )
    if target is None or not target.active or not target.authorization_confirmed:
        raise HTTPException(status_code=404, detail="Approved model target not found.")
    try:
        suite = load_model_agent_suite()
    except ModelAgentEvaluationError as exc:
        raise HTTPException(
            status_code=500,
            detail="The committed model gateway evaluation suite is unavailable.",
        ) from exc

    settings = get_settings()
    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    assessment_started = perf_counter()
    case_responses: list[AgentRuntimeEvaluationCaseResponse] = []
    ground_truth_cases: list[GroundTruthCase] = []
    for test in suite.tests:
        case_started = perf_counter()
        model_response: str | None = None
        proposed_action: dict[str, object] | None = None
        try:
            proposal = request_model_action(
                endpoint=target.endpoint,
                model_name=target.model_name,
                test=test,
                timeout_seconds=settings.model_timeout_seconds,
            )
            model_response = proposal.model_response
            proposed_action = {
                "action_type": proposal.action_type,
                "tool_name": proposal.tool_name,
                "target": proposal.target,
                "arguments": proposal.arguments,
                "page_excerpt": proposal.page_excerpt,
            }
            analysis = analyze_agent_action(
                action_type=proposal.action_type,
                tool_name=proposal.tool_name,
                target=proposal.target,
                arguments=proposal.arguments,
                page_excerpt=proposal.page_excerpt,
            )
            action_type = proposal.action_type
            tool_name = proposal.tool_name
            target_value = proposal.target
            enforcement_path = f"gateway_{analysis.verdict}"
            passed = analysis.verdict == test.expected_verdict
            ground_truth_cases.append(
                GroundTruthCase(
                    expected_verdict=test.expected_verdict,
                    actual_verdict=analysis.verdict,
                    elapsed_ms=round((perf_counter() - case_started) * 1000),
                )
            )
        except ModelAgentEvaluationError as exc:
            analysis = rejected_model_output_analysis(str(exc))
            action_type = "other"
            tool_name = "model_action_parser"
            target_value = None
            enforcement_path = "model_output_rejected"
            passed = False

        record = AgentActionRecord(
            organization_id=actor.organization_id,
            system_id=system.id,
            created_by_user_id=actor.user_id,
            action_type=action_type,
            tool_name=tool_name,
            target=target_value,
            decision_source="model_runtime_evaluation",
            evaluation_run_id=run_id,
            evaluation_case_id=test.test_id,
            evaluation_expected_verdict=test.expected_verdict,
            request_sha256=analysis.request_sha256,
            request_characters=analysis.request_characters,
            verdict=analysis.verdict,
            signals=[
                {
                    "code": signal.code,
                    "severity": signal.severity,
                    "message": signal.message,
                }
                for signal in analysis.signals
            ],
            recommendation=analysis.recommendation,
            review_state=_review_state_for_verdict(analysis.verdict),
            model_response_evidence=(
                protect_evidence(model_response[:12_000]) if model_response else None
            ),
            proposal_evidence=(
                protect_evidence(json.dumps(proposed_action, sort_keys=True))
                if proposed_action
                else None
            ),
        )
        db.add(record)
        db.flush()
        case_responses.append(
            AgentRuntimeEvaluationCaseResponse(
                test_id=test.test_id,
                action_id=record.id,
                expected_verdict=test.expected_verdict,
                actual_verdict=analysis.verdict,
                passed=passed,
                signals=[
                    AgentSecuritySignalResponse(
                        code=signal.code,
                        severity=signal.severity,
                        message=signal.message,
                    )
                    for signal in analysis.signals
                ],
                enforcement_path=cast(
                    Literal[
                        "gateway_allowed",
                        "gateway_quarantined",
                        "gateway_blocked",
                        "model_output_rejected",
                    ],
                    enforcement_path,
                ),
                model_response=model_response,
                proposed_action=proposed_action,
            )
        )

    failed_tests = sum(not case.passed for case in case_responses)
    completed_at = datetime.now(UTC)
    metrics = calculate_assessment_metrics(
        ground_truth_cases,
        planned_tests=len(suite.tests),
        assessment_duration_ms=round((perf_counter() - assessment_started) * 1000),
    )
    assessment = AgentRuntimeAssessmentRecord(
        id=run_id,
        organization_id=actor.organization_id,
        system_id=system.id,
        created_by_user_id=actor.user_id,
        target_id=target.id,
        model_name=target.model_name,
        execution_mode="model_to_gateway",
        suite_name=suite.suite_name,
        corpus_version=suite.version,
        corpus_digest=suite.digest,
        scoring_rule_version=suite.scoring_rule_version,
        planned_tests=metrics.planned_tests,
        executed_tests=metrics.executed_tests,
        skipped_tests=metrics.skipped_tests,
        unsupported_tests=metrics.unsupported_tests,
        metrics=metrics.as_dict(),
        started_at=started_at,
        completed_at=completed_at,
    )
    db.add(assessment)
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="agent_runtime_evaluation.model_gateway_run",
        resource_type="agent_runtime_evaluation",
        resource_id=run_id,
        details={
            "system_id": system.id,
            "target_id": target.id,
            "model_name": target.model_name,
            "suite_name": suite.suite_name,
            "total_tests": len(case_responses),
            "failed_tests": failed_tests,
            "executed_tests": metrics.executed_tests,
        },
    )
    db.commit()
    return AgentRuntimeEvaluationResponse(
        run_id=run_id,
        system_id=system.id,
        suite_name=suite.suite_name,
        corpus_version=suite.version,
        corpus_digest=suite.digest,
        scoring_rule_version=suite.scoring_rule_version,
        total_tests=len(case_responses),
        passed_tests=len(case_responses) - failed_tests,
        failed_tests=failed_tests,
        evaluation_status="failed" if failed_tests else "passed",
        metrics=_metrics_to_response(metrics),
        cases=case_responses,
    )


@router.get(
    "/evaluations/{run_id}",
    response_model=AgentRuntimeEvaluationResponse,
)
def get_agent_runtime_evaluation(
    run_id: str,
    db: DBSession,
) -> AgentRuntimeEvaluationResponse:
    """Reproduce a saved evaluation report from its persisted run evidence."""
    validate_identifier(run_id, "run_id")
    actor = request_actor(db)
    assessment = db.scalar(
        select(AgentRuntimeAssessmentRecord).where(
            AgentRuntimeAssessmentRecord.id == run_id,
            AgentRuntimeAssessmentRecord.organization_id == actor.organization_id,
        )
    )
    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Agent runtime assessment not found.",
        )
    records = db.scalars(
        select(AgentActionRecord)
        .where(
            AgentActionRecord.organization_id == actor.organization_id,
            AgentActionRecord.evaluation_run_id == assessment.id,
        )
        .order_by(AgentActionRecord.created_at.asc())
    ).all()
    cases = [
        AgentRuntimeEvaluationCaseResponse(
            test_id=record.evaluation_case_id or "unknown",
            action_id=record.id,
            expected_verdict=cast(
                Literal["allowed", "quarantined", "blocked"],
                record.evaluation_expected_verdict,
            ),
            actual_verdict=cast(
                Literal["allowed", "quarantined", "blocked"], record.verdict
            ),
            passed=(
                record.evaluation_expected_verdict == record.verdict
                and not _model_output_rejected(record)
            ),
            signals=[
                AgentSecuritySignalResponse(
                    code=signal["code"],
                    severity=cast(Literal["low", "medium", "high"], signal["severity"]),
                    message=signal["message"],
                )
                for signal in record.signals
            ],
            enforcement_path=_stored_enforcement_path(record),
            model_response=(
                reveal_evidence(record.model_response_evidence)
                if record.model_response_evidence
                else None
            ),
            proposed_action=_stored_proposal(record.proposal_evidence),
        )
        for record in records
    ]
    failed_tests = sum(not case.passed for case in cases)
    return AgentRuntimeEvaluationResponse(
        run_id=assessment.id,
        system_id=assessment.system_id,
        suite_name=assessment.suite_name,
        corpus_version=assessment.corpus_version,
        corpus_digest=assessment.corpus_digest,
        scoring_rule_version=assessment.scoring_rule_version,
        total_tests=assessment.planned_tests,
        passed_tests=len(cases) - failed_tests,
        failed_tests=failed_tests,
        evaluation_status="failed" if failed_tests else "passed",
        metrics=AgentRuntimeMetricsResponse.model_validate(assessment.metrics),
        cases=cases,
    )


@router.get("/actions", response_model=AgentActionSummary)
def list_agent_actions(db: DBSession, limit: int = 50) -> AgentActionSummary:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")
    records = db.scalars(
        tenant_actions_query(db)
        .order_by(AgentActionRecord.created_at.desc())
        .limit(limit)
    ).all()
    return AgentActionSummary(
        total_actions=len(records),
        allowed=sum(record.verdict == "allowed" for record in records),
        pending_review=sum(
            record.review_state == "pending_review" for record in records
        ),
        blocked=sum(record.verdict == "blocked" for record in records),
        recent_actions=[action_to_response(record) for record in records],
    )


@router.post(
    "/actions/{action_id}/review",
    response_model=AgentActionResponse,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def review_agent_action(
    action_id: str,
    request: AgentActionReviewRequest,
    db: DBSession,
) -> AgentActionResponse:
    validate_identifier(action_id, "action_id")
    record = db.scalar(
        tenant_actions_query(db).where(AgentActionRecord.id == action_id)
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Agent action not found.")
    if record.review_state != "pending_review":
        raise HTTPException(
            status_code=409,
            detail="Only actions awaiting review can be decided.",
        )
    if record.verdict == "blocked":
        raise HTTPException(
            status_code=409,
            detail="Blocked actions cannot be approved by exception.",
        )
    actor = request_actor(db)
    if request.decision == "approve_exception" and actor.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Only an administrator can approve an action by exception.",
        )
    record.review_state = (
        "approved_exception" if request.decision == "approve_exception" else "rejected"
    )
    record.review_notes = request.notes.strip()
    record.reviewed_by_user_id = actor.user_id
    record.reviewed_at = datetime.now(UTC)
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="agent_action.review",
        resource_type="agent_action_inspection",
        resource_id=record.id,
        details={"decision": request.decision, "review_state": record.review_state},
    )
    db.commit()
    db.refresh(record)
    return action_to_response(record)


def _review_state_for_verdict(verdict: str) -> str:
    if verdict == "allowed":
        return "auto_approved"
    if verdict == "quarantined":
        return "pending_review"
    return "rejected"


def _metrics_to_response(metrics: AssessmentMetrics) -> AgentRuntimeMetricsResponse:
    return AgentRuntimeMetricsResponse.model_validate(metrics.as_dict())


def _stored_enforcement_path(
    record: AgentActionRecord,
) -> Literal[
    "not_applicable",
    "gateway_allowed",
    "gateway_quarantined",
    "gateway_blocked",
    "model_output_rejected",
]:
    if record.decision_source != "model_runtime_evaluation":
        return "not_applicable"
    if _model_output_rejected(record):
        return "model_output_rejected"
    return cast(
        Literal["gateway_allowed", "gateway_quarantined", "gateway_blocked"],
        f"gateway_{record.verdict}",
    )


def _model_output_rejected(record: AgentActionRecord) -> bool:
    return any(
        signal["code"] == "model_action_output_rejected" for signal in record.signals
    )


def _stored_proposal(protected_value: str | None) -> dict[str, object] | None:
    if not protected_value:
        return None
    try:
        value = json.loads(reveal_evidence(protected_value))
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _enforcement_response(
    record: AgentActionRecord,
    enforcement_mode: str,
    *,
    idempotent_replay: bool = False,
) -> AgentEnforcementResponse:
    decision_by_verdict = {
        "allowed": "allow",
        "quarantined": "require_review",
        "blocked": "deny",
    }
    decision = decision_by_verdict[record.verdict]
    return AgentEnforcementResponse(
        action=action_to_response(record),
        decision=cast(Literal["allow", "require_review", "deny"], decision),
        execution_permitted=(decision == "allow" or enforcement_mode == "observe"),
        enforcement_mode=cast(Literal["enforce", "observe"], enforcement_mode),
        idempotent_replay=idempotent_replay,
    )
