import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db.models import AuditLog


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    checked_entries: int
    invalid_entry_id: str | None = None


def _entry_hash(
    *,
    previous_hash: str | None,
    organization_id: str,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict[str, str | int | bool | None],
) -> str:
    serialized_details = json.dumps(details, sort_keys=True, separators=(",", ":"))
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
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()


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
    _lock_organization_audit_chain(db, organization_id)
    previous = db.scalar(
        select(AuditLog)
        .where(AuditLog.organization_id == organization_id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
        .with_for_update()
    )
    previous_hash = previous.entry_hash if previous else None
    normalized_details = details or {}
    entry = AuditLog(
        organization_id=organization_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=normalized_details,
        previous_hash=previous_hash,
        entry_hash=_entry_hash(
            previous_hash=previous_hash,
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=normalized_details,
        ),
    )
    db.add(entry)
    return entry


def _lock_organization_audit_chain(db: Session, organization_id: str) -> None:
    """Serialize each PostgreSQL organization's audit chain within the transaction."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:organization_id))"),
            {"organization_id": organization_id},
        )


def verify_audit_chain(db: Session, organization_id: str) -> AuditChainVerification:
    records = db.scalars(
        select(AuditLog)
        .where(AuditLog.organization_id == organization_id)
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    ).all()
    previous_hash: str | None = None

    for record in records:
        expected_hash = _entry_hash(
            previous_hash=previous_hash,
            organization_id=record.organization_id,
            actor_id=record.actor_id,
            action=record.action,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            details=record.details,
        )
        if record.previous_hash != previous_hash or record.entry_hash != expected_hash:
            return AuditChainVerification(
                valid=False,
                checked_entries=len(records),
                invalid_entry_id=record.id,
            )
        previous_hash = record.entry_hash

    return AuditChainVerification(valid=True, checked_entries=len(records))
