import os

import httpx

from app.core.config import get_settings
from app.core.execution import model_execution_gate
from app.core.security import validate_local_http_url

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"


class OllamaAdapter:
    def __init__(self, base_url: str | None = None) -> None:
        configured_url = base_url or os.getenv(
            "OLLAMA_BASE_URL",
            DEFAULT_OLLAMA_BASE_URL,
        )
        self.base_url = validate_local_http_url(configured_url, "OLLAMA_BASE_URL")

    def health(self) -> dict[str, str]:
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return {
                "status": "error",
                "provider": "ollama",
                "endpoint": self.base_url,
                "detail": str(exc),
            }

        return {
            "status": "ok",
            "provider": "ollama",
            "endpoint": self.base_url,
        }

    def list_models(self) -> dict:
        response = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
        response.raise_for_status()
        return response.json()

    def generate(self, model: str, prompt: str) -> dict:
        settings = get_settings()
        model_execution_gate.acquire()
        try:
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": settings.model_max_output_tokens},
                },
                timeout=settings.model_timeout_seconds,
            )
            response.raise_for_status()
            return response.json()
        finally:
            model_execution_gate.release()
