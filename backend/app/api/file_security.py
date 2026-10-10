from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.evidence import protect_evidence, reveal_evidence
from app.core.security import require_api_key, validate_identifier
from app.db.models import AISystemProfileRecord, FileSecurityScanRecord, UserRole
from app.models.file_security import (
    FileSecurityScanResponse,
    FileSecurityScanSummary,
    FileSecuritySignalResponse,
    OCRExtractionResponse,
    OCRSignalResponse,
)
from app.services.audit import write_audit_log
from app.services.file_security import FileSecuritySignal, analyze_file_upload
from app.services.ocr_security import (
    SUPPORTED_OCR_TYPES,
    OCRRunnerError,
    extract_text_in_sandbox,
)
from app.services.rag_security import analyze_rag_source

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


def ocr_to_response(record: FileSecurityScanRecord) -> OCRExtractionResponse:
    status_value = record.ocr_status or "not_run"
    signals = record.ocr_signals or []
    return OCRExtractionResponse(
        scan=scan_to_response(record),
        extraction_status=cast(
            Literal["completed", "quarantined", "not_run"], status_value
        ),
        extracted_text_sha256=record.ocr_text_sha256,
        extracted_text_characters=record.ocr_text_characters,
        extracted_text=(
            reveal_evidence(record.ocr_text_evidence)
            if record.ocr_text_evidence
            else None
        ),
        signals=[
            OCRSignalResponse(
                code=signal["code"],
                severity=cast(Literal["low", "medium", "high"], signal["severity"]),
                message=signal["message"],
            )
            for signal in signals
        ],
    )


async def _read_bounded_upload(file: UploadFile, max_file_scan_bytes: int) -> bytes:
    content = await file.read(max_file_scan_bytes + 1)
    await file.close()
    if len(content) > max_file_scan_bytes:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the configured static-scan size limit.",
        )
    return content


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
    content = await _read_bounded_upload(file, settings.max_file_scan_bytes)

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


@router.post(
    "/ocr",
    response_model=OCRExtractionResponse,
    status_code=201,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
async def scan_file_with_ocr(
    db: DBSession,
    file: Upload,
    system_id: OptionalSystemId = None,
) -> OCRExtractionResponse:
    """Extract image text only through the fixed no-egress OCR sandbox."""
    settings = get_settings()
    content = await _read_bounded_upload(file, settings.max_file_scan_bytes)
    if system_id is not None:
        validate_identifier(system_id, "system_id")
        require_tenant_system(db, system_id)

    analysis = analyze_file_upload(filename=file.filename, content=content)
    actor = request_actor(db)
    scan_signals = _signal_dicts(analysis.signals)
    ocr_signals: list[dict[str, str]] = []
    verdict = analysis.verdict
    recommendation = analysis.recommendation
    ocr_status = "not_run"
    extracted_text: str | None = None
    extracted_text_sha256: str | None = None
    extracted_text_characters: int | None = None

    if verdict == "allowed" and analysis.detected_type not in SUPPORTED_OCR_TYPES:
        verdict = "quarantined"
        recommendation = (
            "OCR is supported only for PNG and JPEG inputs. Do not forward this "
            "file to a model path."
        )
        ocr_signals.append(
            _ocr_signal(
                "ocr_unsupported_type",
                "medium",
                "The static file check passed, but this type is not supported by "
                "the OCR sandbox.",
            )
        )
    elif verdict == "allowed" and not settings.ocr_enabled:
        verdict = "quarantined"
        recommendation = (
            "OCR is disabled. Do not forward this file to a model or RAG path."
        )
        ocr_signals.append(
            _ocr_signal(
                "ocr_disabled",
                "high",
                "OCR was requested but the isolated OCR service is disabled.",
            )
        )
    elif verdict == "allowed":
        try:
            extraction = extract_text_in_sandbox(
                content=content,
                filename=analysis.safe_filename,
                detected_type=analysis.detected_type,
                runner_url=settings.ocr_runner_url,
                runner_token=settings.ocr_runner_token,
                timeout_seconds=settings.ocr_timeout_seconds,
            )
        except OCRRunnerError:
            verdict = "quarantined"
            recommendation = (
                "OCR could not complete safely. Keep the file out of the model "
                "and RAG paths."
            )
            ocr_signals.append(
                _ocr_signal(
                    "ocr_sandbox_unavailable",
                    "high",
                    "The isolated OCR service did not return a trustworthy result.",
                )
            )
        else:
            extracted_text = extraction.text
            extracted_text_sha256 = extraction.sha256
            extracted_text_characters = extraction.characters
            text_analysis = analyze_rag_source(extraction.text)
            ocr_signals = [
                _ocr_signal(
                    f"ocr_{signal.code}",
                    signal.severity,
                    signal.message,
                )
                for signal in text_analysis.signals
            ]
            if text_analysis.verdict == "quarantined":
                verdict = "quarantined"
                ocr_status = "quarantined"
                recommendation = (
                    "Extracted text is quarantined. Do not index or forward it "
                    "until an authorized reviewer records a decision."
                )
            else:
                ocr_status = "completed"
                recommendation = (
                    "Static and OCR text checks passed. Forward only through a "
                    "model-specific safe input path."
                )

    combined_signals = [*scan_signals, *ocr_signals]
    record = FileSecurityScanRecord(
        organization_id=actor.organization_id,
        system_id=system_id,
        created_by_user_id=actor.user_id,
        filename=analysis.safe_filename,
        declared_content_type=(file.content_type or "")[:255] or None,
        detected_type=analysis.detected_type,
        sha256=analysis.sha256,
        file_size_bytes=analysis.file_size_bytes,
        verdict=verdict,
        signals=combined_signals,
        recommendation=recommendation,
        ocr_status=ocr_status,
        ocr_text_evidence=(
            protect_evidence(extracted_text) if extracted_text else None
        ),
        ocr_text_sha256=extracted_text_sha256,
        ocr_text_characters=extracted_text_characters,
        ocr_signals=ocr_signals,
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="file_security.ocr",
        resource_type="file_security_scan",
        resource_id=record.id,
        details={
            "detected_type": record.detected_type,
            "verdict": record.verdict,
            "ocr_status": record.ocr_status,
            "ocr_signal_count": len(ocr_signals),
        },
    )
    db.commit()
    db.refresh(record)
    return ocr_to_response(record)


@router.get(
    "/scans/{scan_id}/ocr",
    response_model=OCRExtractionResponse,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def get_ocr_extraction(scan_id: str, db: DBSession) -> OCRExtractionResponse:
    validate_identifier(scan_id, "scan_id")
    record = db.scalar(
        tenant_scans_query(db).where(FileSecurityScanRecord.id == scan_id)
    )
    if record is None or record.ocr_status is None:
        raise HTTPException(status_code=404, detail="OCR extraction record not found.")
    return ocr_to_response(record)


def _signal_dicts(signals: list[FileSecuritySignal]) -> list[dict[str, str]]:
    return [
        {
            "code": signal.code,
            "severity": signal.severity,
            "message": signal.message,
        }
        for signal in signals
    ]


def _ocr_signal(
    code: str,
    severity: Literal["low", "medium", "high"],
    message: str,
) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


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
