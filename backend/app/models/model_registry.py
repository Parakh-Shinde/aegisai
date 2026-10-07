from pydantic import BaseModel, Field, field_validator

from app.core.security import validate_local_http_url


class ModelCapabilityProfile(BaseModel):
    text_generation: bool = False
    vision: bool = False
    audio: bool = False
    image_input: bool = False
    structured_output: bool = False
    function_calling: bool = False
    tool_use: bool = False
    agentic_behavior: bool = False
    long_context: bool = False
    rag: bool = False
    reasoning: bool = False
    streaming: bool = False
    code_generation: bool = False
    multilingual: bool = False
    memory: bool = False


class RegisteredModel(BaseModel):
    model_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        examples=["ollama:qwen2.5:3b"],
    )
    provider: str = Field(..., min_length=1, max_length=50, examples=["ollama"])
    name: str = Field(..., min_length=1, max_length=100, examples=["qwen2.5"])
    version: str = Field(..., min_length=1, max_length=50, examples=["3b"])
    endpoint: str = Field(
        ...,
        min_length=1,
        max_length=300,
        examples=["http://localhost:11434"],
    )
    deployment_type: str = Field(..., min_length=1, max_length=50, examples=["local"])
    capabilities: ModelCapabilityProfile
    authentication: str = Field(default="none", max_length=50, examples=["none"])


class ModelRegistrationRequest(BaseModel):
    provider: str = Field(..., min_length=1, max_length=50, examples=["ollama"])
    name: str = Field(..., min_length=1, max_length=100, examples=["qwen2.5"])
    version: str = Field(..., min_length=1, max_length=50, examples=["3b"])
    endpoint: str = Field(
        ...,
        min_length=1,
        max_length=300,
        examples=["http://localhost:11434"],
    )
    deployment_type: str = Field(..., min_length=1, max_length=50, examples=["local"])
    capabilities: ModelCapabilityProfile
    authentication: str = Field(default="none", max_length=50, examples=["none"])

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return validate_local_http_url(value, "endpoint")
