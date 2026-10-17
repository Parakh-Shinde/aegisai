import base64
import hashlib
import hmac
import os
from datetime import UTC, datetime

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.auth import (
    AccountStatusRequest,
    AdminPasswordResetRequest,
    APITokenCreateRequest,
    ChangePasswordRequest,
    LocalStagingBootstrapRequest,
    MFAActivationRequest,
    MFAEnrollmentRequest,
    activate_mfa,
    admin_reset_user_password,
    begin_mfa_enrollment,
    bootstrap_existing_local_lab_administrator,
    change_own_password,
    create_api_token,
    revoke_api_token,
    update_organization_user_status,
)
from app.core.auth import (
    Actor,
    create_access_token,
    get_current_actor,
    hash_password,
    request_actor,
    require_roles,
    verify_password,
    verify_totp_code,
)
from app.db.models import AuditLog, Base, Organization, User, UserRole
from app.services.audit import (
    export_audit_logs_csv,
    verify_audit_chain,
    write_audit_log,
)


def totp_code(secret: str, timestamp: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(
        key,
        (timestamp // 30).to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


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
        assert verify_audit_chain(db, organization.id).valid

        second.details = {"tampered": True}
        assert not verify_audit_chain(db, organization.id).valid


def test_local_actor_is_available_from_the_request_db_session(monkeypatch) -> None:
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "false")
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        actor = get_current_actor(db, None)

        assert request_actor(db) == actor


def test_local_staging_bootstrap_replaces_known_development_account(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGISAI_ENVIRONMENT", "development")
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("AEGISAI_ALLOW_LOCAL_STAGING_BOOTSTRAP", "true")
    monkeypatch.setenv("AEGISAI_BOOTSTRAP_TOKEN", "bootstrap-token")
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(
            id="organization-1",
            name="Local AEGISAI Lab",
            slug="local-lab",
        )
        development_user = User(
            id="user-local",
            organization_id=organization.id,
            email="local-analyst@aegisai.local",
            password_hash=hash_password("local-development-only"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([organization, development_user])
        db.commit()

        token = bootstrap_existing_local_lab_administrator(
            LocalStagingBootstrapRequest(
                email="admin@example.local",
                password="long-unique-staging-password",
            ),
            db,
            "bootstrap-token",
        )

        users = db.scalars(select(User).order_by(User.email)).all()

    assert token.access_token.count(".") == 2
    assert len(users) == 2
    assert not next(user for user in users if user.id == "user-local").is_active
    administrator = next(user for user in users if user.email == "admin@example.local")
    assert administrator.is_active
    assert administrator.role == UserRole.ADMIN


def test_password_change_revokes_old_token_and_returns_a_new_one(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        user = User(
            id="user-1",
            organization_id=organization.id,
            email="analyst@example.com",
            password_hash=hash_password("old-password-123"),
            role=UserRole.SECURITY_ANALYST,
        )
        db.add_all([organization, user])
        db.commit()
        old_token = create_access_token(user)
        actor = Actor(
            user_id=user.id,
            organization_id=organization.id,
            role=user.role,
            email=user.email,
        )

        response = change_own_password(
            ChangePasswordRequest(
                current_password="old-password-123",
                new_password="new-password-456",
            ),
            actor,
            db,
        )

        assert verify_password("new-password-456", user.password_hash)
        assert user.auth_epoch == 1
        with pytest.raises(HTTPException, match="revoked"):
            get_current_actor(
                db,
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=old_token),
            )
        assert get_current_actor(
            db,
            HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=response.access_token
            ),
        ).user_id == user.id


def test_admin_can_reset_and_disable_another_user_with_audit_evidence() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        administrator = User(
            id="admin-1",
            organization_id=organization.id,
            email="admin@example.com",
            password_hash=hash_password("admin-password-123"),
            role=UserRole.ADMIN,
        )
        analyst = User(
            id="analyst-1",
            organization_id=organization.id,
            email="analyst@example.com",
            password_hash=hash_password("analyst-password-123"),
            role=UserRole.SECURITY_ANALYST,
        )
        db.add_all([organization, administrator, analyst])
        db.commit()
        actor = Actor(
            user_id=administrator.id,
            organization_id=organization.id,
            role=administrator.role,
            email=administrator.email,
        )

        reset_response = admin_reset_user_password(
            analyst.id,
            AdminPasswordResetRequest(new_password="replacement-password-456"),
            actor,
            db,
        )
        disabled_response = update_organization_user_status(
            analyst.id,
            AccountStatusRequest(is_active=False),
            actor,
            db,
        )

        assert reset_response.is_active
        assert verify_password("replacement-password-456", analyst.password_hash)
        assert analyst.auth_epoch == 2
        assert not disabled_response.is_active
        actions = db.scalars(
            select(AuditLog.action).order_by(AuditLog.created_at)
        ).all()
        assert actions == ["user.password_reset", "user.disabled"]


def test_mfa_enrollment_requires_valid_totp_and_revokes_old_sessions(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        user = User(
            id="user-1",
            organization_id=organization.id,
            email="analyst@example.com",
            password_hash=hash_password("analyst-password-123"),
            role=UserRole.SECURITY_ANALYST,
        )
        db.add_all([organization, user])
        db.commit()
        actor = Actor(user.id, organization.id, user.role, user.email)
        old_token = create_access_token(user)

        enrollment = begin_mfa_enrollment(
            MFAEnrollmentRequest(current_password="analyst-password-123"), actor, db
        )
        assert enrollment.secret not in (user.mfa_pending_secret_encrypted or "")
        timestamp = int(datetime.now(UTC).timestamp())
        code = totp_code(enrollment.secret, timestamp)
        assert verify_totp_code(enrollment.secret, code, at_time=timestamp)

        response = activate_mfa(MFAActivationRequest(code=code), actor, db)
        assert user.mfa_enabled
        assert user.auth_epoch == 1
        with pytest.raises(HTTPException, match="revoked"):
            get_current_actor(
                db,
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=old_token),
            )
        assert get_current_actor(
            db,
            HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=response.access_token
            ),
        ).user_id == user.id


def test_admin_can_issue_and_revoke_a_scoped_api_token(monkeypatch) -> None:
    monkeypatch.setenv("AEGISAI_AUTH_REQUIRED", "true")
    monkeypatch.setenv("AEGISAI_JWT_SECRET", "a" * 32)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        administrator = User(
            id="admin-1",
            organization_id=organization.id,
            email="admin@example.com",
            password_hash=hash_password("admin-password-123"),
            role=UserRole.ADMIN,
        )
        db.add_all([organization, administrator])
        db.commit()
        actor = Actor(
            administrator.id,
            organization.id,
            administrator.role,
            administrator.email,
        )
        created = create_api_token(
            APITokenCreateRequest(
                name="ci-evaluator",
                scopes={"read", "write"},
                expires_in_days=30,
            ),
            actor,
            db,
        )
        api_actor = get_current_actor(
            db,
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=created.token),
        )
        assert api_actor.authentication_method == "api_token"
        assert api_actor.role == UserRole.SECURITY_ANALYST
        require_roles(UserRole.SECURITY_ANALYST, UserRole.ADMIN)(api_actor)

        revoke_api_token(created.id, actor, db)
        with pytest.raises(HTTPException, match="revoked"):
            get_current_actor(
                db,
                HTTPAuthorizationCredentials(
                    scheme="Bearer", credentials=created.token
                ),
            )



def test_audit_csv_export_neutralizes_spreadsheet_formulas() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        organization = Organization(id="organization-1", name="Org One", slug="org-one")
        entry = AuditLog(
            id="audit-1",
            organization_id=organization.id,
            actor_id=None,
            action="=HYPERLINK(\"https://attacker.example\")",
            resource_type="test",
            resource_id=None,
            details={},
            previous_hash=None,
            entry_hash="hash",
        )
        db.add_all([organization, entry])
        db.flush()

        csv_output = export_audit_logs_csv([entry])

    assert "'=HYPERLINK" in csv_output
