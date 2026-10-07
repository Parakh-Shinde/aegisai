import hmac
import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
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


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=256)
    role: UserRole


def validate_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid email address is required.",
        )
    return normalized


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


@router.post("/login")
def login(request: LoginRequest, db: DBSession) -> TokenResponse:
    email = validate_email(request.email)
    user = db.scalar(select(User).where(User.email == email))
    if (
        user is None
        or not user.is_active
        or not verify_password(
            request.password,
            user.password_hash,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

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


@router.post(
    "/users", response_model=CurrentUserResponse, status_code=status.HTTP_201_CREATED
)
def create_organization_user(
    request: CreateUserRequest,
    actor: CurrentActor,
    db: DBSession,
) -> CurrentUserResponse:
    if actor.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization administrators can create users.",
        )

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

    return CurrentUserResponse(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
    )
