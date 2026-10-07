import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.core.auth import (  # noqa: E402
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.models import AuditLog, Base, Organization, User, UserRole  # noqa: E402
from app.services.audit import write_audit_log  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402


def test_password_hash_and_jwt_token(monkeypatch) -> None:
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    password_hash = hash_password("a-long-enough-test-password")
    user = User(
        id="user-1",
        organization_id="organization-1",
        email="analyst@example.com",
        password_hash=password_hash,
        role=UserRole.SECURITY_ANALYST,
    )

    assert verify_password("a-long-enough-test-password", password_hash)
    assert not verify_password("wrong-password", password_hash)
    assert create_access_token(user).count(".") == 2


def test_audit_log_hashes_chain_within_organization() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        user = User(
            id="user-1",
            organization_id=organization.id,
            email="admin@example.com",
            password_hash="not-used-in-this-test",
            role=UserRole.ADMIN,
        )
        db.add_all([organization, user])
        db.flush()
        first = write_audit_log(
            db,
            organization_id=organization.id,
            actor_id=user.id,
            action="model.register",
            resource_type="model",
            resource_id="ollama:test:latest",
        )
        second = write_audit_log(
            db,
            organization_id=organization.id,
            actor_id=user.id,
            action="security_test.run",
            resource_type="security_test_result",
            resource_id="test-1",
        )
        db.commit()

        records = db.scalars(select(AuditLog).order_by(AuditLog.created_at)).all()
        assert len(records) == 2
        assert first.previous_hash is None
        assert second.previous_hash == first.entry_hash
        assert first.entry_hash != second.entry_hash
