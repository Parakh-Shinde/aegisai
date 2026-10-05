from pydantic import BaseModel, Field


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
    model_id: str = Field(..., examples=["ollama:qwen2.5:3b"])
    provider: str = Field(..., examples=["ollama"])
    name: str = Field(..., examples=["qwen2.5"])
    version: str = Field(..., examples=["3b"])
    endpoint: str = Field(..., examples=["http://localhost:11434"])
    deployment_type: str = Field(..., examples=["local"])
    capabilities: ModelCapabilityProfile
    authentication: str = Field(default="none", examples=["none"])

class ModelRegistrationRequest(BaseModel):
    provider: str = Field(..., examples=["ollama"])
    name: str = Field(..., examples=["qwen2.5"])
    version: str = Field(..., examples=["3b"])
    endpoint: str = Field(..., examples=["http://localhost:11434"])
    deployment_type: str = Field(..., examples=["local"])
    capabilities: ModelCapabilityProfile
    authentication: str = Field(default="none", examples=["none"])
