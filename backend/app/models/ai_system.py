from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

SystemType = Literal["assistant", "rag", "agent", "multimodal", "model_api"]
DeploymentExposure = Literal["internal", "partner", "public"]
DataClassification = Literal["public", "internal", "confidential", "regulated"]

SUPPORTED_MODALITIES = {"text", "image", "document", "audio", "video"}
SUPPORTED_CAPABILITIES = {
    "rag",
    "agent_tools",
    "browser",
    "code_execution",
    "external_apis",
    "customer_data",
    "multi_tenant",
}


class AISystemProfileRequest(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    system_type: SystemType
    deployment_exposure: DeploymentExposure
    data_classification: DataClassification
    input_modalities: set[str] = Field(default_factory=lambda: {"text"})
    capabilities: set[str] = Field(default_factory=set)

    @field_validator("input_modalities")
    @classmethod
    def validate_input_modalities(cls, value: set[str]) -> set[str]:
        if not value:
            raise ValueError("At least one input modality is required.")
        unknown = value - SUPPORTED_MODALITIES
        if unknown:
            raise ValueError(
                f"Unsupported input modalities: {', '.join(sorted(unknown))}"
            )
        return value

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: set[str]) -> set[str]:
        unknown = value - SUPPORTED_CAPABILITIES
        if unknown:
            raise ValueError(f"Unsupported capabilities: {', '.join(sorted(unknown))}")
        return value

    @model_validator(mode="after")
    def align_type_with_attack_surface(self) -> "AISystemProfileRequest":
        if self.system_type == "rag":
            self.capabilities.add("rag")
        if self.system_type == "agent":
            self.capabilities.add("agent_tools")
        if self.system_type == "multimodal" and self.input_modalities == {"text"}:
            raise ValueError(
                "A multimodal system must declare at least one non-text input."
            )
        return self


class AISystemProfileResponse(BaseModel):
    id: str
    name: str
    description: str | None
    system_type: SystemType
    deployment_exposure: DeploymentExposure
    data_classification: DataClassification
    input_modalities: list[str]
    capabilities: list[str]
    profile_version: int
    created_at: datetime
    updated_at: datetime


class CoveragePackResponse(BaseModel):
    pack_id: str
    title: str
    category: str
    status: Literal["available", "planned"]
    reason: str


class AISystemCoverageResponse(BaseModel):
    system_id: str
    profile_version: int
    automated_test_coverage_percent: float
    available_packs: int
    planned_packs: int
    packs: list[CoveragePackResponse]
