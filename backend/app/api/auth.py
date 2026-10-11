import hmac
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, cast
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import (
    Actor,
    api_token_hash,
    api_token_prefix,
    create_access_token,
    generate_api_token,
    generate_totp_secret,
    get_current_actor,
    hash_password,
    protect_mfa_secret,
    reveal_mfa_secret,
    verify_password,
    verify_totp_code,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import get_login_rate_limiter
from app.db.models import ApiTokenRecord, Organization, User, UserRole
from app.services.audit import write_audit_log

router = APIRouter(prefix="/auth", tags=["Authentication"])
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DBSession = Annotated[Session, Depends(get_db)]
BootstrapToken = Annotated[str | None, Header()]
CurrentActor = Annotated[Actor, Depends(get_current_actor)]


class BootstrapRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=160)
    organization_slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class CurrentUserResponse(BaseModel):
    user_id: str
    organization_id: str
    email: str
    role: UserRole
    mfa_enabled: bool


class OrganizationUserResponse(CurrentUserResponse):
    is_active: bool
    last_login_at: datetime | None


class MFAStatusResponse(BaseModel):
    enabled: bool
    enrolled_at: datetime | None
    pending_enrollment: bool


class MFAEnrollmentRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)


class MFAEnrollmentResponse(BaseModel):
    secret: str
    otpauth_uri: str
    expires_at: datetime


class MFAActivationRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFADisableRequest(MFAActivationRequest):
    current_password: str = Field(min_length=1, max_length=256)


APITokenScope = Literal["read", "write"]


class APITokenCreateRequest(BaseModel):
    name: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._ -]*$",
    )
    scopes: set[APITokenScope] = Field(min_length=1)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class APITokenResponse(BaseModel):
    id: str
    name: str
    token_prefix: str
    role: UserRole
    scopes: list[APITokenScope]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class APITokenCreatedResponse(APITokenResponse):
    token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


class AccountStatusRequest(BaseModel):
    is_active: bool


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=256)
    role: UserRole


class LocalStagingBootstrapRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=256)


def validate_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid email address is required.",
        )
    return normalized


def require_admin(actor: Actor) -> None:
    require_interactive_session(actor)
    if actor.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization administrators can perform this action.",
        )


def require_interactive_session(actor: Actor) -> None:
    if actor.authentication_method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="An interactive user session is required for identity operations.",
        )


def response_for_user(user: User) -> OrganizationUserResponse:
    return OrganizationUserResponse(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
        mfa_enabled=user.mfa_enabled,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
    )


def response_for_api_token(record: ApiTokenRecord) -> APITokenResponse:
    return APITokenResponse(
        id=record.id,
        name=record.name,
        token_prefix=record.token_prefix,
        role=record.role,
        scopes=sorted(cast(list[APITokenScope], record.scopes)),
        created_at=record.created_at,
        expires_at=record.expires_at,
        last_used_at=record.last_used_at,
        revoked_at=record.revoked_at,
    )


def get_current_user_record(db: Session, actor: Actor) -> User:
    return get_organization_user_or_404(db, actor, actor.user_id)


def mfa_status_response(user: User) -> MFAStatusResponse:
    return MFAStatusResponse(
        enabled=user.mfa_enabled,
        enrolled_at=user.mfa_enrolled_at,
        pending_enrollment=user.mfa_pending_secret_encrypted is not None,
    )


def _pending_mfa_secret_or_410(user: User) -> str:
    if (
        user.mfa_pending_secret_encrypted is None
        or user.mfa_pending_created_at is None
    ):
        raise HTTPException(status_code=409, detail="No MFA enrollment is pending.")
    pending_at = user.mfa_pending_created_at
    if pending_at.tzinfo is None:
        pending_at = pending_at.replace(tzinfo=UTC)
    expires_at = pending_at + timedelta(minutes=15)
    if expires_at <= datetime.now(UTC):
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_created_at = None
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="MFA enrollment expired. Start a new enrollment.",
        )
    return reveal_mfa_secret(user.mfa_pending_secret_encrypted)


def get_organization_user_or_404(db: Session, actor: Actor, user_id: str) -> User:
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == actor.organization_id,
        )
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User was not found in this organization.",
        )
    return user


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap_first_administrator(
    request: BootstrapRequest,
    db: DBSession,
    x_bootstrap_token: BootstrapToken,
) -> TokenResponse:
    settings = get_settings()
    if not settings.bootstrap_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bootstrap is disabled. Configure AEGISAI_BOOTSTRAP_TOKEN first.",
        )
    if not x_bootstrap_token or not hmac.compare_digest(
        x_bootstrap_token,
        settings.bootstrap_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bootstrap token.",
        )
    if db.scalar(select(func.count()).select_from(User)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bootstrap has already completed.",
        )

    email = validate_email(request.email)
    organization = Organization(
        name=request.organization_name.strip(),
        slug=request.organization_slug,
    )
    db.add(organization)
    db.flush()
    user = User(
        organization_id=organization.id,
        email=email,
        password_hash=hash_password(request.password),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    db.flush()
    write_audit_log(
        db,
        organization_id=organization.id,
        actor_id=user.id,
        action="organization.bootstrap",
        resource_type="organization",
        resource_id=organization.id,
        details={"administrator_email": email},
    )
    db.commit()

    return TokenResponse(
        access_token=create_access_token(user),
        expires_in_seconds=settings.jwt_expiry_minutes * 60,
    )


@router.post("/local-staging-bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap_existing_local_lab_administrator(
    request: LocalStagingBootstrapRequest,
    db: DBSession,
    x_bootstrap_token: BootstrapToken,
) -> TokenResponse:
    """Safely convert a development local-lab organization to authenticated staging.

    This narrow one-time path exists because development mode automatically
    creates a known-password local account. It is prohibited in production and
    disables that account before creating a real administrator.
    """
    settings = get_settings()
    if (
        not settings.auth_required
        or settings.is_production
        or not settings.allow_local_staging_bootstrap
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local staging bootstrap is not enabled for this environment.",
        )
    if not settings.bootstrap_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Configure AEGISAI_BOOTSTRAP_TOKEN first.",
        )
    if not x_bootstrap_token or not hmac.compare_digest(
        x_bootstrap_token,
        settings.bootstrap_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bootstrap token.",
        )

    organization = db.scalar(
        select(Organization).where(
            Organization.slug == settings.local_organization_slug
        )
    )
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The local development organization does not exist.",
        )
    if db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.organization_id == organization.id,
            User.email != "local-analyst@aegisai.local",
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Local staging bootstrap was already completed or is not applicable."
            ),
        )

    local_user = db.scalar(
        select(User).where(
            User.organization_id == organization.id,
            User.email == "local-analyst@aegisai.local",
        )
    )
    if local_user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The expected local development account was not found.",
        )
    email = validate_email(request.email)
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    local_user.is_active = False
    administrator = User(
        organization_id=organization.id,
        email=email,
        password_hash=hash_password(request.password),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(administrator)
    db.flush()
    write_audit_log(
        db,
        organization_id=organization.id,
        actor_id=administrator.id,
        action="organization.local_staging_bootstrap",
        resource_type="organization",
        resource_id=organization.id,
        details={"administrator_email": email},
    )
    db.commit()
    return TokenResponse(
        access_token=create_access_token(administrator),
        expires_in_seconds=settings.jwt_expiry_minutes * 60,
    )


@router.post("/login")
def login(
    login_request: LoginRequest,
    request: Request,
    db: DBSession,
) -> TokenResponse:
    email = validate_email(login_request.email)
    client_host = request.client.host if request.client else "unknown"
    rate_limit_key = f"{client_host}:{email}"
    rate_limiter = get_login_rate_limiter()
    rate_limiter.check(rate_limit_key)
    user = db.scalar(select(User).where(User.email == email))
    password_valid = (
        user is not None
        and user.is_active
        and verify_password(login_request.password, user.password_hash)
    )
    mfa_valid = (
        password_valid
        and user is not None
        and (
            not user.mfa_enabled
            or (
                login_request.mfa_code is not None
                and user.mfa_secret_encrypted is not None
                and verify_totp_code(
                    reveal_mfa_secret(user.mfa_secret_encrypted),
                    login_request.mfa_code,
                )
            )
        )
    )
    if not mfa_valid or user is None:
        rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email, password, or MFA code.",
        )

    rate_limiter.reset(rate_limit_key)
    user.last_login_at = datetime.now(UTC)
    write_audit_log(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        action="auth.login_mfa" if user.mfa_enabled else "auth.login",
        resource_type="user",
        resource_id=user.id,
    )
    db.commit()
    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in_seconds=settings.jwt_expiry_minutes * 60,
    )


@router.get("/me", response_model=CurrentUserResponse)
def get_current_user(actor: CurrentActor, db: DBSession) -> CurrentUserResponse:
    require_interactive_session(actor)
    return CurrentUserResponse(
        user_id=actor.user_id,
        organization_id=actor.organization_id,
        email=actor.email,
        role=actor.role,
        mfa_enabled=get_current_user_record(db, actor).mfa_enabled,
    )


@router.get("/mfa", response_model=MFAStatusResponse)
def get_mfa_status(actor: CurrentActor, db: DBSession) -> MFAStatusResponse:
    require_interactive_session(actor)
    return mfa_status_response(get_current_user_record(db, actor))


@router.post("/mfa/enroll", response_model=MFAEnrollmentResponse)
def begin_mfa_enrollment(
    enrollment: MFAEnrollmentRequest,
    actor: CurrentActor,
    db: DBSession,
) -> MFAEnrollmentResponse:
    require_interactive_session(actor)
    user = get_current_user_record(db, actor)
    if not verify_password(enrollment.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    if user.mfa_enabled:
        raise HTTPException(
            status_code=409,
            detail="MFA is already enabled for this account.",
        )

    secret = generate_totp_secret()
    now = datetime.now(UTC)
    user.mfa_pending_secret_encrypted = protect_mfa_secret(secret)
    user.mfa_pending_created_at = now
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="auth.mfa_enrollment_started",
        resource_type="user",
        resource_id=user.id,
    )
    db.commit()
    parameters = urlencode({
        "secret": secret,
        "issuer": "AEGISAI",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return MFAEnrollmentResponse(
        secret=secret,
        otpauth_uri=f"otpauth://totp/AEGISAI:{user.email}?{parameters}",
        expires_at=now + timedelta(minutes=15),
    )


@router.post("/mfa/activate", response_model=TokenResponse)
def activate_mfa(
    activation: MFAActivationRequest,
    actor: CurrentActor,
    db: DBSession,
) -> TokenResponse:
    require_interactive_session(actor)
    user = get_current_user_record(db, actor)
    secret = _pending_mfa_secret_or_410(user)
    if not verify_totp_code(secret, activation.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code.")

    now = datetime.now(UTC)
    user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_created_at = None
    user.mfa_enabled = True
    user.mfa_enrolled_at = now
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="auth.mfa_enabled",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True},
    )
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in_seconds=get_settings().jwt_expiry_minutes * 60,
    )


@router.post("/mfa/disable", response_model=TokenResponse)
def disable_mfa(
    disable_request: MFADisableRequest,
    actor: CurrentActor,
    db: DBSession,
) -> TokenResponse:
    require_interactive_session(actor)
    user = get_current_user_record(db, actor)
    if not user.mfa_enabled or user.mfa_secret_encrypted is None:
        raise HTTPException(
            status_code=409,
            detail="MFA is not enabled for this account.",
        )
    if not verify_password(disable_request.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    if not verify_totp_code(
        reveal_mfa_secret(user.mfa_secret_encrypted), disable_request.code
    ):
        raise HTTPException(status_code=401, detail="Invalid MFA code.")

    user.mfa_secret_encrypted = None
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_created_at = None
    user.mfa_enabled = False
    user.mfa_enrolled_at = None
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="auth.mfa_disabled",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True},
    )
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in_seconds=get_settings().jwt_expiry_minutes * 60,
    )


@router.post("/password/change", response_model=TokenResponse)
def change_own_password(
    password_change: ChangePasswordRequest,
    actor: CurrentActor,
    db: DBSession,
) -> TokenResponse:
    require_interactive_session(actor)
    user = get_organization_user_or_404(db, actor, actor.user_id)
    if not verify_password(password_change.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )
    if verify_password(password_change.new_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Choose a password that is different from your current password.",
        )

    user.password_hash = hash_password(password_change.new_password)
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="auth.password_changed",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True},
    )
    db.commit()

    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in_seconds=settings.jwt_expiry_minutes * 60,
    )


@router.get("/users", response_model=list[OrganizationUserResponse])
def list_organization_users(
    actor: CurrentActor,
    db: DBSession,
) -> list[OrganizationUserResponse]:
    require_admin(actor)
    users = db.scalars(
        select(User)
        .where(User.organization_id == actor.organization_id)
        .order_by(User.email)
    ).all()
    return [response_for_user(user) for user in users]


@router.post(
    "/users",
    response_model=OrganizationUserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_organization_user(
    request: CreateUserRequest,
    actor: CurrentActor,
    db: DBSession,
) -> OrganizationUserResponse:
    require_admin(actor)

    email = validate_email(request.email)
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    user = User(
        organization_id=actor.organization_id,
        email=email,
        password_hash=hash_password(request.password),
        role=request.role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        details={"role": user.role.value},
    )
    db.commit()

    return response_for_user(user)


@router.post(
    "/users/{user_id}/password-reset",
    response_model=OrganizationUserResponse,
)
def admin_reset_user_password(
    user_id: str,
    password_reset: AdminPasswordResetRequest,
    actor: CurrentActor,
    db: DBSession,
) -> OrganizationUserResponse:
    require_admin(actor)
    if user_id == actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use the password-change endpoint for your own account.",
        )

    user = get_organization_user_or_404(db, actor, user_id)
    user.password_hash = hash_password(password_reset.new_password)
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="user.password_reset",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True, "target_role": user.role.value},
    )
    db.commit()
    return response_for_user(user)


@router.post("/users/{user_id}/mfa-reset", response_model=OrganizationUserResponse)
def admin_reset_user_mfa(
    user_id: str,
    actor: CurrentActor,
    db: DBSession,
) -> OrganizationUserResponse:
    """Clear a lost authenticator only through an audited Admin recovery path."""
    require_admin(actor)
    if user_id == actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use the MFA disable endpoint for your own account.",
        )
    user = get_organization_user_or_404(db, actor, user_id)
    user.mfa_secret_encrypted = None
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_created_at = None
    user.mfa_enabled = False
    user.mfa_enrolled_at = None
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="user.mfa_reset",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True, "target_role": user.role.value},
    )
    db.commit()
    return response_for_user(user)


@router.get("/api-tokens", response_model=list[APITokenResponse])
def list_api_tokens(actor: CurrentActor, db: DBSession) -> list[APITokenResponse]:
    require_admin(actor)
    records = db.scalars(
        select(ApiTokenRecord)
        .where(ApiTokenRecord.organization_id == actor.organization_id)
        .order_by(ApiTokenRecord.created_at.desc())
    ).all()
    return [response_for_api_token(record) for record in records]


@router.post(
    "/api-tokens",
    response_model=APITokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_api_token(
    token_request: APITokenCreateRequest,
    actor: CurrentActor,
    db: DBSession,
) -> APITokenCreatedResponse:
    """Issue a least-privilege automation token and reveal it exactly once."""
    require_admin(actor)
    name = token_request.name.strip()
    if db.scalar(
        select(ApiTokenRecord).where(
            ApiTokenRecord.organization_id == actor.organization_id,
            ApiTokenRecord.name == name,
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="An API token with this name exists.",
        )

    scopes = sorted(token_request.scopes)
    if "write" in scopes:
        role = UserRole.SECURITY_ANALYST
    else:
        role = UserRole.VIEWER
    raw_token = generate_api_token()
    now = datetime.now(UTC)
    record = ApiTokenRecord(
        organization_id=actor.organization_id,
        created_by_user_id=actor.user_id,
        name=name,
        token_prefix=api_token_prefix(raw_token),
        token_hash=api_token_hash(raw_token),
        role=role,
        scopes=scopes,
        expires_at=now + timedelta(days=token_request.expires_in_days),
    )
    db.add(record)
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="api_token.created",
        resource_type="api_token",
        resource_id=record.id,
        details={"name": record.name, "scopes": ",".join(scopes)},
    )
    db.commit()
    db.refresh(record)
    return APITokenCreatedResponse(
        **response_for_api_token(record).model_dump(),
        token=raw_token,
    )


@router.post("/api-tokens/{token_id}/revoke", response_model=APITokenResponse)
def revoke_api_token(
    token_id: str,
    actor: CurrentActor,
    db: DBSession,
) -> APITokenResponse:
    require_admin(actor)
    record = db.scalar(
        select(ApiTokenRecord).where(
            ApiTokenRecord.id == token_id,
            ApiTokenRecord.organization_id == actor.organization_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="API token was not found.")
    if record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        write_audit_log(
            db,
            organization_id=actor.organization_id,
            actor_id=actor.user_id,
            action="api_token.revoked",
            resource_type="api_token",
            resource_id=record.id,
            details={"name": record.name},
        )
        db.commit()
        db.refresh(record)
    return response_for_api_token(record)


@router.patch(
    "/users/{user_id}/status",
    response_model=OrganizationUserResponse,
)
def update_organization_user_status(
    user_id: str,
    account_status: AccountStatusRequest,
    actor: CurrentActor,
    db: DBSession,
) -> OrganizationUserResponse:
    require_admin(actor)
    if user_id == actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Administrators cannot change the active status of their own account."
            ),
        )

    user = get_organization_user_or_404(db, actor, user_id)
    if user.is_active == account_status.is_active:
        return response_for_user(user)
    if not account_status.is_active and user.role == UserRole.ADMIN:
        active_administrators = db.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.organization_id == actor.organization_id,
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            )
        )
        if (active_administrators or 0) <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="At least one active organization administrator is required.",
            )

    user.is_active = account_status.is_active
    user.auth_epoch += 1
    db.flush()
    write_audit_log(
        db,
        organization_id=actor.organization_id,
        actor_id=actor.user_id,
        action="user.enabled" if user.is_active else "user.disabled",
        resource_type="user",
        resource_id=user.id,
        details={"sessions_revoked": True, "target_role": user.role.value},
    )
    db.commit()
    return response_for_user(user)
