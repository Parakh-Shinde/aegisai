import os
from base64 import urlsafe_b64decode
from dataclasses import dataclass

DEVELOPMENT_JWT_SECRET = "development-only-secret-change-before-production"


@dataclass(frozen=True)
class Settings:
    environment: str
    auth_required: bool
    jwt_secret: str
    jwt_issuer: str
    jwt_expiry_minutes: int
    bootstrap_token: str | None
    local_organization_slug: str
    evidence_encryption_key: str | None

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


def get_settings() -> Settings:
    environment = os.getenv("AEGISAI_ENVIRONMENT", "development")
    auth_required = (
        os.getenv(
            "AEGISAI_AUTH_REQUIRED",
            "true" if environment.lower() == "production" else "false",
        ).lower()
        == "true"
    )
    jwt_secret = os.getenv("AEGISAI_JWT_SECRET", "")
    evidence_encryption_key = os.getenv("AEGISAI_EVIDENCE_ENCRYPTION_KEY") or None

    if environment.lower() == "production" and not auth_required:
        raise RuntimeError("AEGISAI_AUTH_REQUIRED must be true in production.")
    if environment.lower() == "production":
        if (
            not jwt_secret
            or jwt_secret == DEVELOPMENT_JWT_SECRET
            or len(jwt_secret) < 32
        ):
            raise RuntimeError(
                "AEGISAI_JWT_SECRET must be a unique value of at least 32 "
                "characters in production."
            )
        if not evidence_encryption_key:
            raise RuntimeError(
                "AEGISAI_EVIDENCE_ENCRYPTION_KEY is required in production."
            )
        try:
            decoded_key = urlsafe_b64decode(evidence_encryption_key.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as exc:
            raise RuntimeError(
                "AEGISAI_EVIDENCE_ENCRYPTION_KEY must be a valid Fernet key."
            ) from exc
        if len(decoded_key) != 32:
            raise RuntimeError(
                "AEGISAI_EVIDENCE_ENCRYPTION_KEY must be a valid Fernet key."
            )

    return Settings(
        environment=environment,
        auth_required=auth_required,
        jwt_secret=jwt_secret or DEVELOPMENT_JWT_SECRET,
        jwt_issuer=os.getenv("AEGISAI_JWT_ISSUER", "aegisai"),
        jwt_expiry_minutes=max(1, int(os.getenv("AEGISAI_JWT_EXPIRY_MINUTES", "30"))),
        bootstrap_token=os.getenv("AEGISAI_BOOTSTRAP_TOKEN") or None,
        local_organization_slug=os.getenv(
            "AEGISAI_LOCAL_ORGANIZATION_SLUG",
            "local-lab",
        ),
        evidence_encryption_key=evidence_encryption_key,
    )
