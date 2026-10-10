import json
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.database import get_db
from app.core.evidence import protect_evidence, reveal_evidence
from app.core.security import (
    require_api_key,
    require_tool_runner_token,
    validate_identifier,
)
from app.db.models import (
    AISystemProfileRecord,
    ToolEvaluationCaseRecord,
    ToolEvaluationRunRecord,
    ToolEvaluationTargetRecord,
    UserRole,
)
from app.models.tool_evaluations import (
    PromptfooClaimResponse,
    PromptfooCompletionRequest,
    PromptfooFailureRequest,
    ToolCaseOutcome,
    ToolCaseResponse,
    ToolRunDetailResponse,
    ToolRunRequest,
    ToolRunResponse,
    ToolRunStatus,
    ToolTargetRequest,
    ToolTargetResponse,
)
from app.services.audit import write_audit_log
from app.services.promptfoo_adapter import (
    PROMPTFOO_SUPPORTED_SUITES,
    PROMPTFOO_TOOL_NAME,
    build_promptfoo_config,
    case_metadata,
    config_digest,
    parse_promptfoo_report,
    report_digest,
)

router = APIRouter(
    prefix="/tool-evaluations",
    tags=["External Tool Evaluations"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
runner_router = APIRouter(
    prefix="/tool-evaluations/runner",
    tags=["External Tool Runner"],
    dependencies=[Depends(require_tool_runner_token)],
)
DBSession = Annotated[Session, Depends(get_db)]


def _tenant_system(db: Session, system_id: str) -> AISystemProfileRecord:
    actor = request_actor(db)
    system = db.scalar(
        select(AISystemProfileRecord).where(
            AISystemProfileRecord.id == system_id,
            AISystemProfileRecord.organization_id == actor.organization_id,
        )
    )
    if system is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    return system


def _target_response(target: ToolEvaluationTargetRecord) -> ToolTargetResponse:
    return ToolTargetResponse(
        id=target.id,
        system_id=target.system_id,
        name=target.name,
        provider=cast(Literal["ollama"], target.provider),
        endpoint=target.endpoint,
        model_name=target.model_name,
        authorization_confirmed=target.authorization_confirmed,
        active=target.active,
        created_at=target.created_at,
    )


def _run_response(run: ToolEvaluationRunRecord) -> ToolRunResponse:
    return ToolRunResponse(
        id=run.id,
        target_id=run.target_id,
        system_id=run.system_id,
        tool_name=cast(Literal["promptfoo"], run.tool_name),
        tool_version=run.tool_version,
        suite_name=run.suite_name,
        config_digest=run.config_digest,
        status=cast(ToolRunStatus, run.status),
        planned_tests=run.planned_tests,
        executed_tests=run.executed_tests,
        passed_tests=run.passed_tests,
        failed_tests=run.failed_tests,
        skipped_tests=run.skipped_tests,
        report_digest=run.report_digest,
        error_summary=run.error_summary,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


@router.post(
    "/targets",
    response_model=ToolTargetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def create_target(request: ToolTargetRequest, db: DBSession) -> ToolTargetResponse:
    """Register a target only after an analyst confirms authorization to test it."""
    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail="You must confirm authorization before AEGISAI can test a target.",
        )
    validate_identifier(request.system_id, "system_id")
    _tenant_system(db, request.system_id)
    actor = request_actor(db)
    existing = db.scalar(
        select(ToolEvaluationTargetRecord).where(
            ToolEvaluationTargetRecord.organization_id == actor.organization_id,
            ToolEvaluationTargetRecord.name == request.name,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=409, detail="A target with this name already exists."
        )
    target = ToolEvaluationTargetRecord(
        organization_id=actor.organization_id,
        system_id=request.system_id,
        created_by_user_id=actor.user_id,
        name=request.name,
        provider=request.provider,
        endpoint=request.endpoint,
        model_name=request.model_name,
        authorization_confirmed=True,
    )
    db.add(target)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="tool_evaluation.target.create",
        resource_type="tool_evaluation_target",
        resource_id=target.id,
        details={"provider": target.provider, "system_id": target.system_id},
    )
    db.commit()
    db.refresh(target)
    return _target_response(target)


@router.get("/targets", response_model=list[ToolTargetResponse])
def list_targets(db: DBSession) -> list[ToolTargetResponse]:
    actor = request_actor(db)
    targets = db.scalars(
        select(ToolEvaluationTargetRecord)
        .where(ToolEvaluationTargetRecord.organization_id == actor.organization_id)
        .order_by(ToolEvaluationTargetRecord.created_at.desc())
    ).all()
    return [_target_response(target) for target in targets]


@router.post(
    "/runs",
    response_model=ToolRunResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def create_promptfoo_run(request: ToolRunRequest, db: DBSession) -> ToolRunResponse:
    """Create a pending job; only the isolated runner can claim and execute it."""
    validate_identifier(request.target_id, "target_id")
    actor = request_actor(db)
    target = db.scalar(
        select(ToolEvaluationTargetRecord).where(
            ToolEvaluationTargetRecord.id == request.target_id,
            ToolEvaluationTargetRecord.organization_id == actor.organization_id,
        )
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Approved tool target not found.")
    if not target.active or not target.authorization_confirmed:
        raise HTTPException(
            status_code=409, detail="Target is not approved for execution."
        )
    if request.suite_name not in PROMPTFOO_SUPPORTED_SUITES:
        raise HTTPException(status_code=400, detail="Unsupported Promptfoo suite.")

    config = build_promptfoo_config(target.model_name, request.suite_name)
    run = ToolEvaluationRunRecord(
        organization_id=actor.organization_id,
        system_id=target.system_id,
        target_id=target.id,
        created_by_user_id=actor.user_id,
        tool_name=PROMPTFOO_TOOL_NAME,
        tool_version="pending-runner-attestation",
        suite_name=request.suite_name,
        config_digest=config_digest(config),
        status="pending",
        planned_tests=len(config["tests"]),
    )
    db.add(run)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="tool_evaluation.run.create",
        resource_type="tool_evaluation_run",
        resource_id=run.id,
        details={
            "tool": run.tool_name,
            "target_id": target.id,
            "planned_tests": run.planned_tests,
        },
    )
    db.commit()
    db.refresh(run)
    return _run_response(run)


@router.get("/runs", response_model=list[ToolRunResponse])
def list_runs(db: DBSession, limit: int = 50) -> list[ToolRunResponse]:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")
    actor = request_actor(db)
    runs = db.scalars(
        select(ToolEvaluationRunRecord)
        .where(ToolEvaluationRunRecord.organization_id == actor.organization_id)
        .order_by(ToolEvaluationRunRecord.created_at.desc())
        .limit(limit)
    ).all()
    return [_run_response(run) for run in runs]


@router.get("/runs/{run_id}", response_model=ToolRunDetailResponse)
def get_run(run_id: str, db: DBSession) -> ToolRunDetailResponse:
    validate_identifier(run_id, "run_id")
    actor = request_actor(db)
    run = db.scalar(
        select(ToolEvaluationRunRecord).where(
            ToolEvaluationRunRecord.id == run_id,
            ToolEvaluationRunRecord.organization_id == actor.organization_id,
        )
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Tool evaluation run not found.")
    cases = db.scalars(
        select(ToolEvaluationCaseRecord)
        .where(
            ToolEvaluationCaseRecord.run_id == run.id,
            ToolEvaluationCaseRecord.organization_id == actor.organization_id,
        )
        .order_by(ToolEvaluationCaseRecord.created_at.asc())
    ).all()
    return ToolRunDetailResponse(
        **_run_response(run).model_dump(),
        cases=[
            ToolCaseResponse(
                id=case.id,
                external_case_id=case.external_case_id,
                outcome=cast(ToolCaseOutcome, case.outcome),
                score=case.score,
                prompt=reveal_evidence(case.prompt_evidence)
                if case.prompt_evidence
                else None,
                response=(
                    reveal_evidence(case.response_evidence)
                    if case.response_evidence
                    else None
                ),
                assertions=case.assertions,
                created_at=case.created_at,
            )
            for case in cases
        ],
    )


@runner_router.post("/runs/{run_id}/claim", response_model=PromptfooClaimResponse)
def claim_promptfoo_run(run_id: str, db: DBSession) -> PromptfooClaimResponse:
    validate_identifier(run_id, "run_id")
    run = db.get(ToolEvaluationRunRecord, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Tool evaluation run not found.")
    if run.status != "pending":
        raise HTTPException(
            status_code=409, detail="Tool evaluation run is not pending."
        )
    target = db.get(ToolEvaluationTargetRecord, run.target_id)
    if target is None or not target.active or not target.authorization_confirmed:
        raise HTTPException(
            status_code=409, detail="Tool evaluation target is not active."
        )
    config = build_promptfoo_config(target.model_name, run.suite_name)
    if config_digest(config) != run.config_digest:
        raise HTTPException(
            status_code=409, detail="Run configuration integrity check failed."
        )
    run.status = "running"
    run.started_at = datetime.now(UTC)
    db.commit()
    return PromptfooClaimResponse(
        run_id=run.id,
        provider_id=f"ollama:chat:{target.model_name}",
        ollama_base_url=target.endpoint,
        config=config,
    )


@runner_router.post("/runs/{run_id}/complete", response_model=ToolRunResponse)
def complete_promptfoo_run(
    run_id: str,
    request: PromptfooCompletionRequest,
    db: DBSession,
) -> ToolRunResponse:
    validate_identifier(run_id, "run_id")
    run = db.get(ToolEvaluationRunRecord, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Tool evaluation run not found.")
    if run.status != "running":
        raise HTTPException(
            status_code=409, detail="Tool evaluation run is not running."
        )
    try:
        report_size = len(json.dumps(request.report, separators=(",", ":")))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422, detail="Promptfoo report must be JSON."
        ) from exc
    if report_size > 900_000:
        raise HTTPException(
            status_code=413, detail="Promptfoo report exceeds the import limit."
        )

    cases = parse_promptfoo_report(request.report)
    if not cases:
        raise HTTPException(
            status_code=422,
            detail="Promptfoo report did not contain importable result rows.",
        )
    if len(cases) > run.planned_tests:
        raise HTTPException(
            status_code=422, detail="Promptfoo report has unexpected result rows."
        )
    if len({case.external_case_id for case in cases}) != len(cases):
        raise HTTPException(
            status_code=422, detail="Promptfoo report has duplicate case identifiers."
        )
    for case in cases:
        assertions = list(case.assertions)
        context = case_metadata(run.suite_name, case.external_case_id)
        if context:
            assertions.append({"aegisai_case_context": context})
        db.add(
            ToolEvaluationCaseRecord(
                organization_id=run.organization_id,
                run_id=run.id,
                external_case_id=case.external_case_id,
                outcome=case.outcome,
                score=case.score,
                prompt_evidence=_protect_optional(case.prompt),
                response_evidence=_protect_optional(case.response),
                assertions=assertions,
            )
        )
    run.tool_version = request.tool_version.strip()
    run.status = "completed"
    reported_skipped = sum(case.outcome == "skipped" for case in cases)
    run.executed_tests = len(cases) - reported_skipped
    run.passed_tests = sum(case.outcome == "passed" for case in cases)
    run.failed_tests = sum(case.outcome in {"failed", "error"} for case in cases)
    run.skipped_tests = run.planned_tests - run.executed_tests
    run.report_digest = report_digest(request.report)
    run.completed_at = datetime.now(UTC)
    write_audit_log(
        db,
        organization_id=run.organization_id,
        actor_id=None,
        action="tool_evaluation.run.complete",
        resource_type="tool_evaluation_run",
        resource_id=run.id,
        details={
            "tool": run.tool_name,
            "executed_tests": run.executed_tests,
            "failed_tests": run.failed_tests,
        },
    )
    db.commit()
    db.refresh(run)
    return _run_response(run)


@runner_router.post("/runs/{run_id}/fail", response_model=ToolRunResponse)
def fail_promptfoo_run(
    run_id: str,
    request: PromptfooFailureRequest,
    db: DBSession,
) -> ToolRunResponse:
    validate_identifier(run_id, "run_id")
    run = db.get(ToolEvaluationRunRecord, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Tool evaluation run not found.")
    if run.status not in {"pending", "running"}:
        raise HTTPException(
            status_code=409, detail="Tool evaluation run is already final."
        )
    run.status = "failed"
    run.error_summary = request.error_summary.strip()
    run.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(run)
    return _run_response(run)


def _protect_optional(value: str | None) -> str | None:
    if value is None:
        return None
    return protect_evidence(value[:12_000])
