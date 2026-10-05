from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.adapters import router as adapters_router
from app.api.model_registry import router as model_registry_router
from app.api.security_tests import router as security_tests_router
from app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AEGISAI API",
    description="AI Security Immune System Backend API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(model_registry_router)
app.include_router(adapters_router)
app.include_router(security_tests_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AEGISAI backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "aegisai-api"}