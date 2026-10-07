import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str
    auth_required: bool
    jwt_secret: str
    jwt_issuer: str
    jwt_expiry_minutes: int
    bootstrap_token: str | None
    local_organization_slug: str

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

    if environment.lower() == "production" and not auth_required:
        raise RuntimeError("AEGISAI_AUTH_REQUIRED must be true in production.")
    if environment.lower() == "production" and len(jwt_secret) < 32:
        raise RuntimeError(
            "AEGISAI_JWT_SECRET must be at least 32 characters in production."
        )

    return Settings(
        environment=environment,
        auth_required=auth_required,
        jwt_secret=jwt_secret or "development-only-secret-change-before-production",
        jwt_issuer=os.getenv("AEGISAI_JWT_ISSUER", "aegisai"),
        jwt_expiry_minutes=max(1, int(os.getenv("AEGISAI_JWT_EXPIRY_MINUTES", "30"))),
        bootstrap_token=os.getenv("AEGISAI_BOOTSTRAP_TOKEN") or None,
        local_organization_slug=os.getenv(
            "AEGISAI_LOCAL_ORGANIZATION_SLUG",
            "local-lab",
        ),
    )
