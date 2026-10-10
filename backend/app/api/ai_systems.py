from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.api.security_tests import build_release_gate_response
from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.database import get_db
from app.core.security import require_api_key
from app.db.models import (
    AgentActionRecord,
    AgentRuntimeAssessmentRecord,
    AISystemProfileRecord,
    FileSecurityScanRecord,
    RAGSourceRecord,
    SecurityTestResultRecord,
    ToolEvaluationRunRecord,
    ToolEvaluationTargetRecord,
    UserRole,
)
from app.models.ai_system import (
    AISystemCoverageResponse,
    AISystemProfileRequest,
    AISystemProfileResponse,
    AISystemReleaseDecisionResponse,
    CoveragePackResponse,
    DataClassification,
    DeploymentExposure,
    EvidenceStatus,
    SystemReleaseDecision,
    SystemReleaseEvidenceResponse,
    SystemType,
)
from app.services.audit import write_audit_log
from app.services.coverage import build_coverage_plan

router = APIRouter(
    prefix="/ai-systems",
    tags=["AI System Profiles"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
DBSession = Annotated[Session, Depends(get_db)]


def tenant_profiles_query(db: Session) -> Select[AISystemProfileRecord]:
    return select(AISystemProfileRecord).where(
        AISystemProfileRecord.organization_id == request_actor(db).organization_id
    )


def profile_to_response(record: AISystemProfileRecord) -> AISystemProfileResponse:
    return AISystemProfileResponse(
        id=record.id,
        name=record.name,
        description=record.description,
        system_type=cast(SystemType, record.system_type),
        deployment_exposure=cast(DeploymentExposure, record.deployment_exposure),
        data_classification=cast(DataClassification, record.data_classification),
        input_modalities=sorted(record.input_modalities),
        capabilities=sorted(record.capabilities),
        profile_version=record.profile_version,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def get_tenant_profile(db: Session, system_id: str) -> AISystemProfileRecord:
    record = db.scalar(
        tenant_profiles_query(db).where(AISystemProfileRecord.id == system_id)
    )
    if record is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    return record


def _evidence(
    source: str,
    status_value: EvidenceStatus,
    summary: str,
    records: Sequence[object],
) -> SystemReleaseEvidenceResponse:
    return SystemReleaseEvidenceResponse(
        source=source,
        status=status_value,
        summary=summary,
        evidence_count=len(records),
        evidence_ids=[
            str(getattr(record, "id", getattr(record, "test_id", "unknown")))
            for record in records[:5]
        ],
    )


def _decision_from_evidence(
    evidence: list[SystemReleaseEvidenceResponse],
) -> SystemReleaseDecision:
    if any(item.status == "fail" for item in evidence):
        return "fail"
    if any(item.status == "manual_review_required" for item in evidence):
        return "manual_review_required"
    return "pass"


@router.post(
    "/",
    response_model=AISystemProfileResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def create_ai_system_profile(
    request: AISystemProfileRequest,
    db: DBSession,
) -> AISystemProfileResponse:
    actor = request_actor(db)
    existing = db.scalar(
        tenant_profiles_query(db).where(
            AISystemProfileRecord.name == request.name.strip()
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="AI system profile name already exists.",
        )

    record = AISystemProfileRecord(
        organization_id=actor.organization_id,
        created_by_user_id=actor.user_id,
        name=request.name.strip(),
        description=request.description.strip() if request.description else None,
        system_type=request.system_type,
        deployment_exposure=request.deployment_exposure,
        data_classification=request.data_classification,
        input_modalities=sorted(request.input_modalities),
        capabilities=sorted(request.capabilities),
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="ai_system_profile.create",
        resource_type="ai_system_profile",
        resource_id=record.id,
        details={
            "system_type": request.system_type,
            "deployment_exposure": request.deployment_exposure,
        },
    )
    db.commit()
    db.refresh(record)
    return profile_to_response(record)


@router.get("/", response_model=list[AISystemProfileResponse])
def list_ai_system_profiles(db: DBSession) -> list[AISystemProfileResponse]:
    records = db.scalars(
        tenant_profiles_query(db).order_by(AISystemProfileRecord.updated_at.desc())
    ).all()
    return [profile_to_response(record) for record in records]


@router.patch(
    "/{system_id}",
    response_model=AISystemProfileResponse,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def replace_ai_system_profile(
    system_id: str,
    request: AISystemProfileRequest,
    db: DBSession,
) -> AISystemProfileResponse:
    record = get_tenant_profile(db, system_id)
    actor = request_actor(db)
    conflicting = db.scalar(
        tenant_profiles_query(db).where(
            AISystemProfileRecord.name == request.name.strip(),
            AISystemProfileRecord.id != record.id,
        )
    )
    if conflicting is not None:
        raise HTTPException(
            status_code=409,
            detail="AI system profile name already exists.",
        )

    record.name = request.name.strip()
    record.description = request.description.strip() if request.description else None
    record.system_type = request.system_type
    record.deployment_exposure = request.deployment_exposure
    record.data_classification = request.data_classification
    record.input_modalities = sorted(request.input_modalities)
    record.capabilities = sorted(request.capabilities)
    record.profile_version += 1
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="ai_system_profile.update",
        resource_type="ai_system_profile",
        resource_id=record.id,
        details={"profile_version": record.profile_version},
    )
    db.commit()
    db.refresh(record)
    return profile_to_response(record)


@router.get("/{system_id}", response_model=AISystemProfileResponse)
def get_ai_system_profile(
    system_id: str,
    db: DBSession,
) -> AISystemProfileResponse:
    return profile_to_response(get_tenant_profile(db, system_id))


@router.get("/{system_id}/coverage", response_model=AISystemCoverageResponse)
def get_ai_system_coverage(
    system_id: str,
    db: DBSession,
) -> AISystemCoverageResponse:
    record = get_tenant_profile(db, system_id)
    plan = build_coverage_plan(
        input_modalities=set(record.input_modalities),
        capabilities=set(record.capabilities),
        deployment_exposure=record.deployment_exposure,
        data_classification=record.data_classification,
    )
    return AISystemCoverageResponse(
        system_id=record.id,
        profile_version=record.profile_version,
        automated_test_coverage_percent=plan.automated_test_coverage_percent,
        available_packs=plan.available_packs,
        partial_packs=plan.partial_packs,
        planned_packs=plan.planned_packs,
        packs=[
            CoveragePackResponse(
                pack_id=pack.pack_id,
                title=pack.title,
                category=pack.category,
                status=pack.status,
                reason=pack.reason,
            )
            for pack in plan.packs
        ],
    )


@router.get(
    "/{system_id}/release-decision",
    response_model=AISystemReleaseDecisionResponse,
)
def get_ai_system_release_decision(
    system_id: str,
    db: DBSession,
) -> AISystemReleaseDecisionResponse:
    """Aggregate only evidence linked to one tenant-owned AI system.

    A missing assessment is deliberately reported as manual review rather than a
    passing result. This endpoint is a decision aid and does not execute tests
    or change any evidence.
    """
    system = get_tenant_profile(db, system_id)
    actor = request_actor(db)
    evidence: list[SystemReleaseEvidenceResponse] = []
    limitations: list[str] = []

    targets = list(
        db.scalars(
            select(ToolEvaluationTargetRecord)
            .where(
                ToolEvaluationTargetRecord.organization_id == actor.organization_id,
                ToolEvaluationTargetRecord.system_id == system.id,
                ToolEvaluationTargetRecord.active.is_(True),
                ToolEvaluationTargetRecord.authorization_confirmed.is_(True),
            )
            .order_by(ToolEvaluationTargetRecord.created_at.desc())
        ).all()
    )
    model_names = {target.model_name for target in targets}
    if not targets:
        evidence.append(
            _evidence(
                "model_target",
                "manual_review_required",
                "No approved model target is linked to this AI system.",
                [],
            )
        )
    else:
        evidence.append(
            _evidence(
                "model_target",
                "pass",
                f"{len(targets)} approved model target(s) are linked to this system.",
                targets,
            )
        )

    campaign_records = list(
        db.scalars(
            select(SecurityTestResultRecord)
            .where(
                SecurityTestResultRecord.organization_id == actor.organization_id,
                SecurityTestResultRecord.model.in_(model_names),
            )
            .order_by(SecurityTestResultRecord.created_at.desc())
        ).all()
    ) if model_names else []
    if not campaign_records:
        evidence.append(
            _evidence(
                "security_campaigns",
                "manual_review_required",
                "No security campaign evidence is available for a linked model.",
                [],
            )
        )
    else:
        campaign_statuses = [
            build_release_gate_response(model=model, records=[
                record for record in campaign_records if record.model == model
            ]).decision
            for model in sorted(model_names)
            if any(record.model == model for record in campaign_records)
        ]
        campaign_decision = (
            "fail"
            if "fail" in campaign_statuses
            else "manual_review_required"
            if "manual_review_required" in campaign_statuses
            else "pass"
        )
        evidence.append(
            _evidence(
                "security_campaigns",
                cast(EvidenceStatus, campaign_decision),
                "Release gates were evaluated using evidence from linked "
                "model targets.",
                campaign_records,
            )
        )

    tool_runs = list(
        db.scalars(
            select(ToolEvaluationRunRecord)
            .where(
                ToolEvaluationRunRecord.organization_id == actor.organization_id,
                ToolEvaluationRunRecord.system_id == system.id,
            )
            .order_by(
                ToolEvaluationRunRecord.completed_at.desc(),
                ToolEvaluationRunRecord.created_at.desc(),
            )
        ).all()
    )
    completed_tool_runs = [run for run in tool_runs if run.status == "completed"]
    if not completed_tool_runs:
        evidence.append(
            _evidence(
                "external_tool_evaluation",
                "manual_review_required",
                "No completed authorized external-tool evaluation is linked "
                "to this system.",
                tool_runs,
            )
        )
    else:
        latest_tool_run = completed_tool_runs[0]
        tool_status: EvidenceStatus = (
            "pass" if latest_tool_run.failed_tests == 0 else "manual_review_required"
        )
        evidence.append(
            _evidence(
                "external_tool_evaluation",
                tool_status,
                (
                    f"Latest {latest_tool_run.tool_name} run completed with "
                    f"{latest_tool_run.failed_tests} failed test(s)."
                ),
                [latest_tool_run],
            )
        )

    file_inputs = {"image", "document", "audio", "video"}
    if set(system.input_modalities) & file_inputs:
        scans = list(
            db.scalars(
                select(FileSecurityScanRecord)
                .where(
                    FileSecurityScanRecord.organization_id == actor.organization_id,
                    FileSecurityScanRecord.system_id == system.id,
                )
                .order_by(FileSecurityScanRecord.created_at.desc())
            ).all()
        )
        risky_scans = [scan for scan in scans if scan.verdict != "allowed"]
        scan_status: EvidenceStatus = (
            "manual_review_required"
            if not scans or risky_scans
            else "pass"
        )
        scan_summary = (
            "No file-security scan is linked to this file-capable system."
            if not scans
            else (
                f"{len(risky_scans)} of {len(scans)} linked file scan(s) "
                "require attention."
            )
        )
        evidence.append(_evidence("file_security", scan_status, scan_summary, scans))
    else:
        evidence.append(
            _evidence(
                "file_security",
                "not_applicable",
                "This system profile does not accept file-based inputs.",
                [],
            )
        )

    if "rag" in system.capabilities:
        sources = list(
            db.scalars(
                select(RAGSourceRecord)
                .where(
                    RAGSourceRecord.organization_id == actor.organization_id,
                    RAGSourceRecord.system_id == system.id,
                )
                .order_by(RAGSourceRecord.created_at.desc())
            ).all()
        )
        pending_sources = [
            source for source in sources if source.review_state == "pending_review"
        ]
        rag_status: EvidenceStatus = (
            "manual_review_required"
            if not sources or pending_sources
            else "pass"
        )
        rag_summary = (
            "No RAG source inspection is linked to this RAG-enabled system."
            if not sources
            else f"{len(pending_sources)} RAG source(s) remain pending review."
        )
        evidence.append(_evidence("rag_security", rag_status, rag_summary, sources))
    else:
        evidence.append(
            _evidence(
                "rag_security",
                "not_applicable",
                "This system profile does not declare RAG capability.",
                [],
            )
        )

    if "agent_tools" in system.capabilities:
        assessments = list(
            db.scalars(
                select(AgentRuntimeAssessmentRecord)
                .where(
                    AgentRuntimeAssessmentRecord.organization_id
                    == actor.organization_id,
                    AgentRuntimeAssessmentRecord.system_id == system.id,
                )
                .order_by(AgentRuntimeAssessmentRecord.completed_at.desc())
            ).all()
        )
        if not assessments:
            evidence.append(
                _evidence(
                    "agent_runtime",
                    "manual_review_required",
                    "No agent runtime evaluation is linked to this "
                    "tool-enabled system.",
                    [],
                )
            )
        else:
            latest_assessment = assessments[0]
            assessment_actions = list(
                db.scalars(
                    select(AgentActionRecord).where(
                        AgentActionRecord.organization_id == actor.organization_id,
                        AgentActionRecord.evaluation_run_id == latest_assessment.id,
                    )
                ).all()
            )
            failed_cases = [
                action
                for action in assessment_actions
                if action.evaluation_expected_verdict != action.verdict
            ]
            agent_status: EvidenceStatus = (
                "manual_review_required"
                if len(assessment_actions) != latest_assessment.planned_tests
                or failed_cases
                else "pass"
            )
            evidence.append(
                _evidence(
                    "agent_runtime",
                    agent_status,
                    (
                        f"Latest agent runtime evaluation contains {len(failed_cases)} "
                        f"failed case(s) across {len(assessment_actions)} "
                        "recorded action(s)."
                    ),
                    [latest_assessment],
                )
            )
    else:
        evidence.append(
            _evidence(
                "agent_runtime",
                "not_applicable",
                "This system profile does not declare agent tool capability.",
                [],
            )
        )

    coverage = build_coverage_plan(
        input_modalities=set(system.input_modalities),
        capabilities=set(system.capabilities),
        deployment_exposure=system.deployment_exposure,
        data_classification=system.data_classification,
    )
    if coverage.planned_packs:
        limitations.append(
            f"{coverage.planned_packs} applicable coverage pack(s) are not "
            "automated yet."
        )
    limitations.append(
        "The decision applies only to evidence linked to this system profile version."
    )
    decision = _decision_from_evidence(evidence)
    reason = (
        "All applicable linked evidence currently passes."
        if decision == "pass"
        else "One or more required evidence sources need analyst review."
        if decision == "manual_review_required"
        else "One or more linked evidence sources failed the release decision."
    )
    return AISystemReleaseDecisionResponse(
        system_id=system.id,
        profile_version=system.profile_version,
        decision=decision,
        reason=reason,
        generated_at=datetime.now(UTC),
        evidence=evidence,
        coverage_limitations=limitations,
    )
