import hmac
import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import (
    Actor,
    create_access_token,
    get_current_actor,
    hash_password,
    verify_password,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import get_login_rate_limiter
from app.db.models import Organization, User, UserRole
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


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class CurrentUserResponse(BaseModel):
    user_id: str
    organization_id: str
    email: str
    role: UserRole


class OrganizationUserResponse(CurrentUserResponse):
    is_active: bool
    last_login_at: datetime | None


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
    if actor.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization administrators can perform this action.",
        )


def response_for_user(user: User) -> OrganizationUserResponse:
    return OrganizationUserResponse(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
    )


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
    if (
        user is None
        or not user.is_active
        or not verify_password(
            login_request.password,
            user.password_hash,
        )
    ):
        rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    rate_limiter.reset(rate_limit_key)
    user.last_login_at = datetime.now(UTC)
    write_audit_log(
        db,
        organization_id=user.organization_id,
        actor_id=user.id,
        action="auth.login",
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
def get_current_user(actor: CurrentActor) -> CurrentUserResponse:
    return CurrentUserResponse(
        user_id=actor.user_id,
        organization_id=actor.organization_id,
        email=actor.email,
        role=actor.role,
    )


@router.post("/password/change", response_model=TokenResponse)
def change_own_password(
    password_change: ChangePasswordRequest,
    actor: CurrentActor,
    db: DBSession,
) -> TokenResponse:
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
