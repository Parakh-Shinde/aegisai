from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, current_actor, require_roles
from app.core.database import get_db
from app.core.security import require_api_key
from app.db.models import RegisteredModelRecord, UserRole
from app.models.model_registry import ModelRegistrationRequest, RegisteredModel
from app.services.audit import write_audit_log
from app.services.ollama_adapter import OllamaAdapter

router = APIRouter(
    prefix="/models",
    tags=["Model Registry"],
    dependencies=[Depends(require_api_key), Depends(bind_request_actor)],
)
DBSession = Annotated[Session, Depends(get_db)]


def build_model_id(provider: str, name: str, version: str) -> str:
    return f"{provider}:{name}:{version}".lower()


def infer_ollama_capabilities(raw_model: dict) -> dict[str, bool]:
    capabilities = raw_model.get("capabilities", [])
    return {
        "text_generation": "completion" in capabilities,
        "tool_use": "tools" in capabilities,
        "reasoning": True,
        "code_generation": True,
        "multilingual": True,
    }


def to_response(record: RegisteredModelRecord) -> RegisteredModel:
    return RegisteredModel(
        model_id=record.model_id,
        provider=record.provider,
        name=record.name,
        version=record.version,
        endpoint=record.endpoint,
        deployment_type=record.deployment_type,
        capabilities=record.capabilities,
        authentication=record.authentication,
    )


def save_registered_model(
    db: Session,
    model: ModelRegistrationRequest,
) -> RegisteredModelRecord:
    actor = current_actor()
    model_id = build_model_id(model.provider, model.name, model.version)
    existing = db.scalar(
        select(RegisteredModelRecord).where(
            RegisteredModelRecord.organization_id == actor.organization_id,
            RegisteredModelRecord.model_id == model_id,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Model already registered: {model_id}",
        )

    record = RegisteredModelRecord(
        organization_id=actor.organization_id,
        created_by_user_id=actor.user_id,
        model_id=model_id,
        **model.model_dump(),
    )
    db.add(record)
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="model.register",
        resource_type="model",
        resource_id=model_id,
        details={"provider": model.provider},
    )
    db.commit()
    db.refresh(record)
    return record


@router.post(
    "/",
    response_model=RegisteredModel,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def register_model(model: ModelRegistrationRequest, db: DBSession) -> RegisteredModel:
    return to_response(save_registered_model(db, model))


@router.post(
    "/discover/ollama",
    response_model=list[RegisteredModel],
    dependencies=[Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN))],
)
def discover_ollama_models(db: DBSession) -> list[RegisteredModel]:
    adapter = OllamaAdapter()
    discovered = adapter.list_models()
    created_models: list[RegisteredModel] = []

    for raw_model in discovered.get("models", []):
        model_name = raw_model.get("name", "unknown")
        name, _, version = model_name.partition(":")
        model_id = build_model_id("ollama", name, version or "latest")
        existing = db.scalar(
            select(RegisteredModelRecord).where(
                RegisteredModelRecord.organization_id
                == current_actor().organization_id,
                RegisteredModelRecord.model_id == model_id,
            )
        )
        if existing is not None:
            created_models.append(to_response(existing))
            continue
        record = save_registered_model(
            db,
            ModelRegistrationRequest(
                provider="ollama",
                name=name,
                version=version or "latest",
                endpoint=adapter.base_url,
                deployment_type="local",
                authentication="none",
                capabilities=infer_ollama_capabilities(raw_model),
            ),
        )
        created_models.append(to_response(record))

    return created_models


@router.get("/", response_model=list[RegisteredModel])
def list_models(db: DBSession) -> list[RegisteredModel]:
    actor = current_actor()
    records = db.scalars(
        select(RegisteredModelRecord)
        .where(RegisteredModelRecord.organization_id == actor.organization_id)
        .order_by(RegisteredModelRecord.created_at.desc())
    ).all()
    return [to_response(record) for record in records]


@router.get("/{model_id}", response_model=RegisteredModel)
def get_model(model_id: str, db: DBSession) -> RegisteredModel:
    actor = current_actor()
    record = db.scalar(
        select(RegisteredModelRecord).where(
            RegisteredModelRecord.organization_id == actor.organization_id,
            RegisteredModelRecord.model_id == model_id.lower(),
        )
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model not found: {model_id}",
        )
    return to_response(record)
