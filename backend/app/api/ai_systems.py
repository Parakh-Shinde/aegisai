from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.database import get_db
from app.core.security import require_api_key
from app.db.models import AISystemProfileRecord, UserRole
from app.models.ai_system import (
    AISystemCoverageResponse,
    AISystemProfileRequest,
    AISystemProfileResponse,
    CoveragePackResponse,
    DataClassification,
    DeploymentExposure,
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
