from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_api_key, validate_identifier
from app.db.models import AISystemProfileRecord, FileSecurityScanRecord, UserRole
from app.models.file_security import (
    FileSecurityScanResponse,
    FileSecurityScanSummary,
    FileSecuritySignalResponse,
)
from app.services.audit import write_audit_log
from app.services.file_security import analyze_file_upload

router = APIRouter(
    prefix="/file-security",
    tags=["File Security"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
DBSession = Annotated[Session, Depends(get_db)]
Upload = Annotated[UploadFile, File()]
OptionalSystemId = Annotated[str | None, Form()]


def tenant_scans_query(db: Session) -> Select[FileSecurityScanRecord]:
    return select(FileSecurityScanRecord).where(
        FileSecurityScanRecord.organization_id == request_actor(db).organization_id
    )


def scan_to_response(record: FileSecurityScanRecord) -> FileSecurityScanResponse:
    return FileSecurityScanResponse(
        id=record.id,
        system_id=record.system_id,
        filename=record.filename,
        declared_content_type=record.declared_content_type,
        detected_type=record.detected_type,
        sha256=record.sha256,
        file_size_bytes=record.file_size_bytes,
        verdict=cast(Literal["allowed", "quarantined", "blocked"], record.verdict),
        signals=[
            FileSecuritySignalResponse(
                code=signal["code"],
                severity=cast(Literal["low", "medium", "high"], signal["severity"]),
                message=signal["message"],
            )
            for signal in record.signals
        ],
        recommendation=record.recommendation,
        created_at=record.created_at,
    )


def require_tenant_system(
    db: Session,
    system_id: str,
) -> AISystemProfileRecord:
    actor = request_actor(db)
    record = db.scalar(
        select(AISystemProfileRecord).where(
            AISystemProfileRecord.id == system_id,
            AISystemProfileRecord.organization_id == actor.organization_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="AI system profile not found.")
    return record


@router.post(
    "/scans",
    response_model=FileSecurityScanResponse,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
async def scan_file_upload(
    db: DBSession,
    file: Upload,
    system_id: OptionalSystemId = None,
) -> FileSecurityScanResponse:
    settings = get_settings()
    content = await file.read(settings.max_file_scan_bytes + 1)
    await file.close()
    if len(content) > settings.max_file_scan_bytes:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the configured static-scan size limit.",
        )

    if system_id is not None:
        validate_identifier(system_id, "system_id")
        require_tenant_system(db, system_id)

    analysis = analyze_file_upload(filename=file.filename, content=content)
    actor = request_actor(db)
    record = FileSecurityScanRecord(
        organization_id=actor.organization_id,
        system_id=system_id,
        created_by_user_id=actor.user_id,
        filename=analysis.safe_filename,
        declared_content_type=(file.content_type or "")[:255] or None,
        detected_type=analysis.detected_type,
        sha256=analysis.sha256,
        file_size_bytes=analysis.file_size_bytes,
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
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="file_security.scan",
        resource_type="file_security_scan",
        resource_id=record.id,
        details={
            "detected_type": analysis.detected_type,
            "verdict": analysis.verdict,
            "signal_count": len(analysis.signals),
        },
    )
    db.commit()
    db.refresh(record)
    return scan_to_response(record)


@router.get("/scans", response_model=FileSecurityScanSummary)
def list_file_scans(
    db: DBSession,
    limit: int = 50,
) -> FileSecurityScanSummary:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")
    records = db.scalars(
        tenant_scans_query(db)
        .order_by(FileSecurityScanRecord.created_at.desc())
        .limit(limit)
    ).all()
    return FileSecurityScanSummary(
        total_scans=len(records),
        allowed=sum(record.verdict == "allowed" for record in records),
        quarantined=sum(record.verdict == "quarantined" for record in records),
        blocked=sum(record.verdict == "blocked" for record in records),
        recent_scans=[scan_to_response(record) for record in records],
    )
