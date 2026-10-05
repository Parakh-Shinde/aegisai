from fastapi import APIRouter, HTTPException, status

from app.models.model_registry import ModelRegistrationRequest, RegisteredModel
from app.services.ollama_adapter import OllamaAdapter

router = APIRouter(prefix="/models", tags=["Model Registry"])

registered_models: dict[str, RegisteredModel] = {}


def build_model_id(provider: str, name: str, version: str) -> str:
    return f"{provider}:{name}:{version}".lower()


def infer_ollama_capabilities(raw_model: dict) -> dict[str, bool]:
    capabilities = raw_model.get("capabilities", [])

    return {
        "text_generation": "completion" in capabilities,
        "tool_use": "tools" in capabilities,
        "reasoning": True,
        "code_generation": True,
        "multilingual": True,
    }


@router.post(
    "/",
    response_model=RegisteredModel,
    status_code=status.HTTP_201_CREATED,
)
def register_model(model: ModelRegistrationRequest) -> RegisteredModel:
    model_id = build_model_id(model.provider, model.name, model.version)

    if model_id in registered_models:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Model already registered: {model_id}",
        )

    registered_model = RegisteredModel(
        model_id=model_id,
        **model.model_dump(),
    )
    registered_models[model_id] = registered_model
    return registered_model


@router.post("/discover/ollama", response_model=list[RegisteredModel])
def discover_ollama_models() -> list[RegisteredModel]:
    adapter = OllamaAdapter()
    discovered = adapter.list_models()
    created_models: list[RegisteredModel] = []

    for raw_model in discovered.get("models", []):
        model_name = raw_model.get("name", "unknown")
        name_parts = model_name.split(":", maxsplit=1)
        name = name_parts[0]
        version = name_parts[1] if len(name_parts) > 1 else "latest"

        model_id = build_model_id("ollama", name, version)

        if model_id in registered_models:
            continue

        model = ModelRegistrationRequest(
            provider="ollama",
            name=name,
            version=version,
            endpoint=adapter.base_url,
            deployment_type="local",
            authentication="none",
            capabilities=infer_ollama_capabilities(raw_model),
        )

        registered_model = RegisteredModel(
            model_id=model_id,
            **model.model_dump(),
        )
        registered_models[model_id] = registered_model
        created_models.append(registered_model)

    return created_models


@router.get("/", response_model=list[RegisteredModel])
def list_models() -> list[RegisteredModel]:
    return list(registered_models.values())


@router.get("/{model_id}", response_model=RegisteredModel)
def get_model(model_id: str) -> RegisteredModel:
    normalized_model_id = model_id.lower()

    if normalized_model_id not in registered_models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model not found: {model_id}",
        )

    return registered_models[normalized_model_id]