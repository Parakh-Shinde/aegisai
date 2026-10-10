import os
from base64 import urlsafe_b64decode
from dataclasses import dataclass

DEVELOPMENT_JWT_SECRET = "development-only-secret-change-before-production"


@dataclass(frozen=True)
class Settings:
    environment: str
    database_url: str
    auth_required: bool
    jwt_secret: str
    jwt_issuer: str
    jwt_expiry_minutes: int
    bootstrap_token: str | None
    local_organization_slug: str
    evidence_encryption_key: str | None
    jwt_audience: str
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    max_request_body_bytes: int
    max_file_scan_bytes: int
    max_rag_source_characters: int
    max_agent_action_characters: int
    api_docs_enabled: bool
    model_max_output_tokens: int
    model_timeout_seconds: int
    model_max_concurrency: int
    redis_url: str | None
    async_campaigns: bool

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


def get_settings() -> Settings:
    environment = os.getenv("AEGISAI_ENVIRONMENT", "development")
    is_production = environment.lower() == "production"
    database_url = os.getenv("DATABASE_URL", "")
    auth_required = (
        os.getenv(
            "AEGISAI_AUTH_REQUIRED",
            "true" if is_production else "false",
        ).lower()
        == "true"
    )
    jwt_secret = os.getenv("AEGISAI_JWT_SECRET", "")
    evidence_encryption_key = os.getenv("AEGISAI_EVIDENCE_ENCRYPTION_KEY") or None
    cors_origins = _comma_separated_env(
        "AEGISAI_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    trusted_hosts = _comma_separated_env(
        "AEGISAI_TRUSTED_HOSTS",
        "localhost,127.0.0.1,testserver",
    )
    redis_url = os.getenv("AEGISAI_REDIS_URL") or None
    async_campaigns = os.getenv("AEGISAI_ASYNC_CAMPAIGNS", "false").lower() == "true"

    if is_production and not auth_required:
        raise RuntimeError("AEGISAI_AUTH_REQUIRED must be true in production.")
    if is_production:
        if not database_url.startswith("postgresql+"):
            raise RuntimeError("DATABASE_URL must use PostgreSQL in production.")
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
        if not os.getenv("AEGISAI_CORS_ORIGINS") or "*" in cors_origins:
            raise RuntimeError(
                "AEGISAI_CORS_ORIGINS must contain explicit production UI origins."
            )
        if not os.getenv("AEGISAI_TRUSTED_HOSTS") or "*" in trusted_hosts:
            raise RuntimeError(
                "AEGISAI_TRUSTED_HOSTS must contain explicit production host names."
            )
        if not redis_url:
            raise RuntimeError("AEGISAI_REDIS_URL is required in production.")
        if not async_campaigns:
            raise RuntimeError("AEGISAI_ASYNC_CAMPAIGNS must be true in production.")

    return Settings(
        environment=environment,
        database_url=database_url,
        auth_required=auth_required,
        jwt_secret=jwt_secret or DEVELOPMENT_JWT_SECRET,
        jwt_issuer=os.getenv("AEGISAI_JWT_ISSUER", "aegisai"),
        jwt_audience=os.getenv("AEGISAI_JWT_AUDIENCE", "aegisai-api"),
        jwt_expiry_minutes=max(1, int(os.getenv("AEGISAI_JWT_EXPIRY_MINUTES", "30"))),
        bootstrap_token=os.getenv("AEGISAI_BOOTSTRAP_TOKEN") or None,
        local_organization_slug=os.getenv(
            "AEGISAI_LOCAL_ORGANIZATION_SLUG",
            "local-lab",
        ),
        evidence_encryption_key=evidence_encryption_key,
        cors_origins=cors_origins,
        trusted_hosts=trusted_hosts,
        max_request_body_bytes=_bounded_int_env(
            "AEGISAI_MAX_REQUEST_BODY_BYTES",
            default=1_048_576,
            minimum=1_024,
            maximum=1_048_576,
        ),
        max_file_scan_bytes=_bounded_int_env(
            "AEGISAI_MAX_FILE_SCAN_BYTES",
            default=1_048_576,
            minimum=1_024,
            maximum=1_048_576,
        ),
        max_rag_source_characters=_bounded_int_env(
            "AEGISAI_MAX_RAG_SOURCE_CHARACTERS",
            default=65_536,
            minimum=1_024,
            maximum=262_144,
        ),
        max_agent_action_characters=_bounded_int_env(
            "AEGISAI_MAX_AGENT_ACTION_CHARACTERS",
            default=32_768,
            minimum=1_024,
            maximum=131_072,
        ),
        api_docs_enabled=(
            os.getenv(
                "AEGISAI_EXPOSE_API_DOCS",
                "true" if not is_production else "false",
            )
            .lower()
            == "true"
        ),
        model_max_output_tokens=_bounded_int_env(
            "AEGISAI_MODEL_MAX_OUTPUT_TOKENS",
            default=512,
            minimum=1,
            maximum=4_096,
        ),
        model_timeout_seconds=_bounded_int_env(
            "AEGISAI_MODEL_TIMEOUT_SECONDS",
            default=60,
            minimum=5,
            maximum=300,
        ),
        model_max_concurrency=_bounded_int_env(
            "AEGISAI_MODEL_MAX_CONCURRENCY",
            default=2,
            minimum=1,
            maximum=16,
        ),
        redis_url=redis_url,
        async_campaigns=async_campaigns,
    )


def _comma_separated_env(name: str, default: str) -> tuple[str, ...]:
    values = tuple(
        item.strip() for item in os.getenv(name, default).split(",") if item.strip()
    )
    if not values:
        raise RuntimeError(f"{name} must contain at least one value.")
    return values


def _bounded_int_env(name: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value
