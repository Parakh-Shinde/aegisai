from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_api_key, safe_upstream_error
from app.services.ollama_adapter import OllamaAdapter

router = APIRouter(prefix="/adapters", tags=["Adapters"])


class OllamaGenerateRequest(BaseModel):
    model: str = Field(..., min_length=1, max_length=100)
    prompt: str = Field(..., min_length=1, max_length=4000)


@router.get("/ollama/health")
def ollama_health() -> dict[str, str]:
    adapter = OllamaAdapter()
    return adapter.health()


@router.get("/ollama/models", dependencies=[Depends(require_api_key)])
def ollama_models() -> dict:
    adapter = OllamaAdapter()

    try:
        return adapter.list_models()
    except Exception as exc:
        raise safe_upstream_error("Ollama model discovery failed.") from exc


@router.post("/ollama/generate", dependencies=[Depends(require_api_key)])
def ollama_generate(request: OllamaGenerateRequest) -> dict:
    adapter = OllamaAdapter()

    try:
        return adapter.generate(model=request.model, prompt=request.prompt)
    except Exception as exc:
        raise safe_upstream_error("Ollama generation failed.") from exc
