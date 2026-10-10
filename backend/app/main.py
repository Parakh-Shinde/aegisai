from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.adapters import router as adapters_router
from app.api.ai_systems import router as ai_systems_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.file_security import router as file_security_router
from app.api.model_registry import router as model_registry_router
from app.api.security_tests import router as security_tests_router
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.db import models as db_models  # noqa: F401


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        # The dashboard is intentionally served on port 5173 while the API uses
        # port 8000. They are different browser origins but the same local site.
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (
                value
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    await self._send_too_large(scope, receive, send)
                    return
            except ValueError:
                await self._send_too_large(scope, receive, send)
                return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLarge:
            if not response_started:
                await self._send_too_large(scope, receive, send)

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the allowed size."},
        )
        await response(scope, receive, send)


class RequestBodyTooLarge(Exception):
    pass


settings = get_settings()


app = FastAPI(
    title="AEGISAI API",
    description="AI Security Immune System Backend API",
    version="0.1.0",
    docs_url="/docs" if settings.api_docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.api_docs_enabled else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=settings.max_request_body_bytes,
)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(model_registry_router)
app.include_router(ai_systems_router)
app.include_router(adapters_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(file_security_router)
app.include_router(security_tests_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AEGISAI backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "aegisai-api"}


@app.get("/ready")
def readiness_check() -> Response:
    """Confirm dependencies required for accepting work are reachable."""
    checks: dict[str, str] = {}

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"

    if settings.async_campaigns:
        try:
            if not settings.redis_url:
                raise RuntimeError("Redis is not configured")
            client = Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            client.ping()
            client.close()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "unavailable"

    ready = all(status == "ok" for status in checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ok" if ready else "unavailable", "checks": checks},
    )
