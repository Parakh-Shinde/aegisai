from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import bind_request_actor, request_actor, require_roles
from app.core.database import get_db
from app.core.security import require_api_key
from app.db.models import AuditLog, UserRole

router = APIRouter(
    prefix="/audit-logs",
    tags=["Audit Logs"],
    dependencies=[
        Depends(require_api_key),
        Depends(bind_request_actor),
        Depends(require_roles(UserRole.ADMIN)),
    ],
)
DBSession = Annotated[Session, Depends(get_db)]


class AuditLogResponse(BaseModel):
    id: str
    created_at: datetime
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, str | int | bool | None]
    previous_hash: str | None
    entry_hash: str


@router.get("/", response_model=list[AuditLogResponse])
def list_audit_logs(
    db: DBSession,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLogResponse]:
    actor = request_actor(db)
    records = db.scalars(
        select(AuditLog)
        .where(AuditLog.organization_id == actor.organization_id)
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        AuditLogResponse(
            id=record.id,
            created_at=record.created_at,
            actor_id=record.actor_id,
            action=record.action,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            details=record.details,
            previous_hash=record.previous_hash,
            entry_hash=record.entry_hash,
        )
        for record in records
    ]
