import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.adapters import router as adapters_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.model_registry import router as model_registry_router
from app.api.security_tests import router as security_tests_router
from app.db import models as db_models  # noqa: F401


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
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
        return response


app = FastAPI(
    title="AEGISAI API",
    description="AI Security Immune System Backend API",
    version="0.1.0",
)

cors_origins = os.getenv(
    "AEGISAI_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in cors_origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(model_registry_router)
app.include_router(adapters_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(security_tests_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AEGISAI backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "aegisai-api"}
