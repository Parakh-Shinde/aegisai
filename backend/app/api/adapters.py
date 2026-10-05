from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.ollama_adapter import OllamaAdapter

router = APIRouter(prefix="/adapters", tags=["Adapters"])


class OllamaGenerateRequest(BaseModel):
    model: str
    prompt: str


@router.get("/ollama/health")
def ollama_health() -> dict[str, str]:
    adapter = OllamaAdapter()
    return adapter.health()


@router.get("/ollama/models")
def ollama_models() -> dict:
    adapter = OllamaAdapter()

    try:
        return adapter.list_models()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Ollama model discovery failed: {exc}",
        ) from exc


@router.post("/ollama/generate")
def ollama_generate(request: OllamaGenerateRequest) -> dict:
    adapter = OllamaAdapter()

    try:
        return adapter.generate(model=request.model, prompt=request.prompt)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Ollama generation failed: {exc}",
        ) from exc