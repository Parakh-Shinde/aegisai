import json
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    require_agent_gateway_token,
    require_api_key,
    validate_identifier,
)
from app.db.models import AgentActionRecord, AISystemProfileRecord, UserRole
from app.models.agent_security import (
    ActionReviewState,
    ActionType,
    AgentActionInspectionRequest,
    AgentActionResponse,
    AgentActionReviewRequest,
    AgentActionSummary,
    AgentEnforcementResponse,
    AgentSecuritySignalResponse,
)
from app.services.agent_security import analyze_agent_action
from app.services.audit import write_audit_log

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
        "approved_exception"
        if request.decision == "approve_exception"
        else "rejected"
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
