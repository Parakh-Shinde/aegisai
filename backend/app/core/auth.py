import base64
import binascii
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.db.models import ApiTokenRecord, Organization, User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)
password_hasher = PasswordHash.recommended()
ACTOR_SESSION_KEY = "aegisai_request_actor"


@dataclass(frozen=True)
class Actor:
    user_id: str
    organization_id: str
    role: UserRole
    email: str
    authentication_method: str = "session"
    scopes: frozenset[str] = frozenset()


DBSession = Annotated[Session, Depends(get_db)]
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_hasher.verify(password, password_hash)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def verify_totp_code(secret: str, code: str, *, at_time: int | None = None) -> bool:
    """Verify a standard six-digit RFC 6238 TOTP code with a one-step window."""
    if not code.isdecimal() or len(code) != 6:
        return False
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, binascii.Error):
        return False

    timestamp = int(time.time()) if at_time is None else at_time
    for offset in (-30, 0, 30):
        counter = (timestamp + offset) // 30
        digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        position = digest[-1] & 0x0F
        binary = int.from_bytes(digest[position : position + 4], "big") & 0x7FFFFFFF
        candidate = f"{binary % 1_000_000:06d}"
        if hmac.compare_digest(candidate, code):
            return True
    return False


def _mfa_cipher_key() -> bytes:
    """Use an independent configured key in production and a deterministic dev key."""
    settings = get_settings()
    configured_key = settings.mfa_encryption_key
    if configured_key:
        return configured_key.encode("ascii")
    # Development only: avoids persisting plaintext while keeping local setup simple.
    key_material = hashlib.sha256(settings.jwt_secret.encode()).digest()
    return base64.urlsafe_b64encode(key_material)


def protect_mfa_secret(secret: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_mfa_cipher_key()).encrypt(secret.encode("utf-8")).decode("ascii")


def reveal_mfa_secret(encrypted_secret: str) -> str:
    from cryptography.fernet import Fernet, InvalidToken

    try:
        cipher = Fernet(_mfa_cipher_key())
        return cipher.decrypt(encrypted_secret.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Stored MFA material cannot be decrypted. Reset MFA with an "
                "administrator."
            ),
        ) from exc


def generate_api_token() -> str:
    return f"agt_{secrets.token_urlsafe(32)}"


def api_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def api_token_prefix(token: str) -> str:
    return token[:16]


def create_access_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user.id,
        "organization_id": user.organization_id,
        "role": user.role.value,
        "email": user.email,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": str(uuid4()),
        "auth_epoch": user.auth_epoch,
        "amr": ["pwd", "totp"] if user.mfa_enabled else ["pwd"],
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
        actor = get_or_create_local_actor(db)
        db.info[ACTOR_SESSION_KEY] = actor
        return actor

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials.startswith("agt_"):
        return _get_api_token_actor(db, credentials.credentials)

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    organization_id = payload.get("organization_id")
    token_auth_epoch = payload.get("auth_epoch")
    if (
        not isinstance(user_id, str)
        or not isinstance(organization_id, str)
        or not isinstance(token_auth_epoch, int)
        or isinstance(token_auth_epoch, bool)
    ):
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
    if user.auth_epoch != token_auth_epoch:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    actor = Actor(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
        email=user.email,
    )
    db.info[ACTOR_SESSION_KEY] = actor
    return actor


def _get_api_token_actor(db: Session, token: str) -> Actor:
    record = db.scalar(
        select(ApiTokenRecord).where(
            ApiTokenRecord.token_hash == api_token_hash(token),
            ApiTokenRecord.revoked_at.is_(None),
        )
    )
    now = datetime.now(UTC)
    if (
        record is None
        or (
            record.expires_at is not None
            and _as_utc(record.expires_at) <= now
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked API token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # A database lookup and constant-time comparison prevent prefix-only token use.
    if not hmac.compare_digest(record.token_hash, api_token_hash(token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked API token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    record.last_used_at = now
    db.commit()
    actor = Actor(
        user_id=record.created_by_user_id or f"api-token:{record.id}",
        organization_id=record.organization_id,
        role=record.role,
        email=f"api-token:{record.name}",
        authentication_method="api_token",
        scopes=frozenset(scope for scope in record.scopes if isinstance(scope, str)),
    )
    db.info[ACTOR_SESSION_KEY] = actor
    return actor


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def bind_request_actor(
    request: Request,
    actor: Annotated[Actor, Depends(get_current_actor)],
) -> None:
    # get_current_actor attaches this actor to the cached request DB session.
    # Keeping this dependency makes every protected router authenticate first.
    if (
        actor.authentication_method == "api_token"
        and request.method not in {"GET", "HEAD", "OPTIONS"}
        and "write" not in actor.scopes
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This API token requires the 'write' scope for this action.",
        )


def request_actor(db: Session) -> Actor:
    actor = db.info.get(ACTOR_SESSION_KEY)
    if actor is None:
        raise RuntimeError("No authenticated AEGISAI actor is bound to this request.")
    return actor


def require_roles(*allowed_roles: UserRole) -> Callable[[Actor], None]:
    def dependency(actor: Annotated[Actor, Depends(get_current_actor)]) -> None:
        if actor.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role is not permitted to perform this action.",
            )
        if actor.authentication_method == "api_token":
            required_scope = (
                "admin" if allowed_roles == (UserRole.ADMIN,) else "write"
            )
            if required_scope not in actor.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This API token requires the {required_scope!r} scope.",
                )

    return dependency
