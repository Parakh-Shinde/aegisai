from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_api_key, validate_identifier
from app.db.models import AISystemProfileRecord, RAGSourceRecord, UserRole
from app.models.rag_security import (
    RAGSecuritySignalResponse,
    RAGSourceInspectionRequest,
    RAGSourceResponse,
    RAGSourceReviewRequest,
    RAGSourceSummary,
    ReviewState,
    SourceKind,
)
from app.services.audit import write_audit_log
from app.services.rag_security import analyze_rag_source

router = APIRouter(
    prefix="/rag-security",
    tags=["RAG Security"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
DBSession = Annotated[Session, Depends(get_db)]


def tenant_sources_query(db: Session) -> Select[RAGSourceRecord]:
    return select(RAGSourceRecord).where(
        RAGSourceRecord.organization_id == request_actor(db).organization_id
    )


def require_tenant_rag_system(db: Session, system_id: str) -> AISystemProfileRecord:
    actor = request_actor(db)
    record = db.scalar(
        select(AISystemProfileRecord).where(
            AISystemProfileRecord.id == system_id,
            AISystemProfileRecord.organization_id == actor.organization_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    if "rag" not in record.capabilities:
        raise HTTPException(
            status_code=409,
            detail="RAG source inspection requires an AI system with RAG enabled.",
        )
    return record


def source_to_response(record: RAGSourceRecord) -> RAGSourceResponse:
    return RAGSourceResponse(
        id=record.id,
        system_id=record.system_id,
        source_name=record.source_name,
        source_kind=cast(SourceKind, record.source_kind),
        source_reference=record.source_reference,
        content_sha256=record.content_sha256,
        content_characters=record.content_characters,
        verdict=cast(Literal["approved", "quarantined"], record.verdict),
        signals=[
            RAGSecuritySignalResponse(
                code=signal["code"],
                severity=cast(Literal["low", "medium", "high"], signal["severity"]),
                message=signal["message"],
            )
            for signal in record.signals
        ],
        recommendation=record.recommendation,
        review_state=cast(ReviewState, record.review_state),
        review_notes=record.review_notes,
        reviewed_at=record.reviewed_at,
        created_at=record.created_at,
    )


@router.post(
    "/sources/inspect",
    response_model=RAGSourceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def inspect_rag_source(
    request: RAGSourceInspectionRequest,
    db: DBSession,
) -> RAGSourceResponse:
    settings = get_settings()
    if len(request.content) > settings.max_rag_source_characters:
        raise HTTPException(
            status_code=413,
            detail="Source exceeds the configured RAG inspection character limit.",
        )
    validate_identifier(request.system_id, "system_id")
    require_tenant_rag_system(db, request.system_id)
    analysis = analyze_rag_source(request.content)
    actor = request_actor(db)
    review_state = (
        "auto_approved" if analysis.verdict == "approved" else "pending_review"
    )
    record = RAGSourceRecord(
        organization_id=actor.organization_id,
        system_id=request.system_id,
        created_by_user_id=actor.user_id,
        source_name=request.source_name,
        source_kind=request.source_kind,
        source_reference=request.source_reference,
        content_sha256=analysis.content_sha256,
        content_characters=analysis.content_characters,
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
        action="rag_source.inspect",
        resource_type="rag_source",
        resource_id=record.id,
        details={
            "system_id": record.system_id,
            "verdict": record.verdict,
            "signal_count": len(analysis.signals),
        },
    )
    db.commit()
    db.refresh(record)
    return source_to_response(record)


@router.get("/sources", response_model=RAGSourceSummary)
def list_rag_sources(db: DBSession, limit: int = 50) -> RAGSourceSummary:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")
    records = db.scalars(
        tenant_sources_query(db)
        .order_by(RAGSourceRecord.created_at.desc())
        .limit(limit)
    ).all()
    eligible_states = {"auto_approved", "approved_exception"}
    return RAGSourceSummary(
        total_sources=len(records),
        eligible_for_indexing=sum(
            record.review_state in eligible_states for record in records
        ),
        pending_review=sum(
            record.review_state == "pending_review" for record in records
        ),
        quarantined=sum(record.verdict == "quarantined" for record in records),
        recent_sources=[source_to_response(record) for record in records],
    )


@router.post(
    "/sources/{source_id}/review",
    response_model=RAGSourceResponse,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def review_rag_source(
    source_id: str,
    request: RAGSourceReviewRequest,
    db: DBSession,
) -> RAGSourceResponse:
    validate_identifier(source_id, "source_id")
    record = db.scalar(
        tenant_sources_query(db).where(RAGSourceRecord.id == source_id)
    )
    if record is None:
        raise HTTPException(status_code=404, detail="RAG source not found.")
    if record.review_state != "pending_review":
        raise HTTPException(
            status_code=409,
            detail="Only quarantined sources awaiting review can be decided.",
        )
    actor = request_actor(db)
    if request.decision == "approve_exception" and actor.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail=(
                "Only an administrator can approve a quarantined source by "
                "exception."
            ),
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
        action="rag_source.review",
        resource_type="rag_source",
        resource_id=record.id,
        details={"decision": request.decision, "review_state": record.review_state},
    )
    db.commit()
    db.refresh(record)
    return source_to_response(record)
