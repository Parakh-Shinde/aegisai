import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog


def write_audit_log(
    db: Session,
    *,
    organization_id: str,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, str | int | bool | None] | None = None,
) -> AuditLog:
    previous = db.scalar(
        select(AuditLog)
        .where(AuditLog.organization_id == organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    )
    previous_hash = previous.entry_hash if previous else None
    serialized_details = json.dumps(
        details or {}, sort_keys=True, separators=(",", ":")
    )
    hash_input = "|".join(
        [
            previous_hash or "",
            organization_id,
            actor_id or "",
            action,
            resource_type,
            resource_id or "",
            serialized_details,
        ]
    )
    entry = AuditLog(
        organization_id=organization_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        previous_hash=previous_hash,
        entry_hash=hashlib.sha256(hash_input.encode("utf-8")).hexdigest(),
    )
    db.add(entry)
    return entry
