from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.db.models import Organization, User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)
password_hasher = PasswordHash.recommended()
_actor_context: ContextVar["Actor | None"] = ContextVar("aegisai_actor", default=None)


@dataclass(frozen=True)
class Actor:
    user_id: str
    organization_id: str
    role: UserRole
    email: str


DBSession = Annotated[Session, Depends(get_db)]
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_hasher.verify(password, password_hash)


def create_access_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user.id,
        "organization_id": user.organization_id,
        "role": user.role.value,
        "email": user.email,
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def get_or_create_local_actor(db: Session) -> Actor:
    settings = get_settings()
    organization = db.scalar(
        select(Organization).where(
            Organization.slug == settings.local_organization_slug
        )
    )

    if organization is None:
        organization = Organization(
            name="Local AEGISAI Lab",
            slug=settings.local_organization_slug,
        )
        db.add(organization)
        db.flush()

    user = db.scalar(
        select(User).where(
            User.organization_id == organization.id,
            User.email == "local-analyst@aegisai.local",
        )
    )
    if user is None:
        user = User(
            organization_id=organization.id,
            email="local-analyst@aegisai.local",
            password_hash=hash_password("local-development-only"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        db.flush()

    db.commit()
    return Actor(
        user_id=user.id,
        organization_id=organization.id,
        role=user.role,
        email=user.email,
    )


def get_current_actor(
    db: DBSession,
    credentials: BearerCredentials,
) -> Actor:
    settings = get_settings()

    if not settings.auth_required:
        return get_or_create_local_actor(db)

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    organization_id = payload.get("organization_id")
    if not isinstance(user_id, str) or not isinstance(organization_id, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token claims.",
        )

    user = db.get(User, user_id)
    if user is None or not user.is_active or user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or unavailable.",
        )

    return Actor(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
        email=user.email,
    )


def bind_request_actor(
    actor: Annotated[Actor, Depends(get_current_actor)],
) -> None:
    # FastAPI can finalize synchronous yield dependencies in a different
    # context from the one that created their ContextVar token. Setting the
    # request-local value without a yield avoids that cross-context reset.
    # AnyIO runs each request in an isolated copied context.
    _actor_context.set(actor)


def current_actor() -> Actor:
    actor = _actor_context.get()
    if actor is None:
        raise RuntimeError("No authenticated AEGISAI actor is bound to this request.")
    return actor


def require_roles(*allowed_roles: UserRole):
    def dependency() -> None:
        actor = current_actor()
        if actor.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role is not permitted to perform this action.",
            )

    return dependency
