from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.security import validate_approved_application_url, validate_local_http_url

ToolRunStatus = Literal["pending", "running", "completed", "failed"]
ToolCaseOutcome = Literal["passed", "failed", "error", "skipped"]
ToolTargetProvider = Literal["ollama", "openai_compatible"]


class ToolTargetRequest(BaseModel):
    system_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=120)
    provider: ToolTargetProvider = "ollama"
    endpoint: str = Field(min_length=1, max_length=512)
    model_name: str = Field(min_length=1, max_length=120)
    authorization_confirmed: bool

    @field_validator("name", "model_name")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value must not be empty.")
        return value

    @field_validator("endpoint")
    @classmethod
    def normalize_endpoint(cls, value: str) -> str:
        return value.strip().rstrip("/")

    def model_post_init(self, __context: Any, /) -> None:
        if self.provider == "ollama":
            validate_local_http_url(self.endpoint, "endpoint")
            return
        validate_approved_application_url(self.endpoint, "endpoint")


class ToolTargetResponse(BaseModel):
    id: str
    system_id: str
    name: str
    provider: ToolTargetProvider
    endpoint: str
    model_name: str
    authorization_confirmed: bool
    active: bool
    created_at: datetime


class ToolRunRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=128)
    suite_name: Literal[
        "aegisai_local_safety_smoke", "aegisai_ai_security_baseline_v1"
    ] = "aegisai_ai_security_baseline_v1"


class ToolRunResponse(BaseModel):
    id: str
    target_id: str
    system_id: str
    tool_name: Literal["promptfoo"]
    tool_version: str
    suite_name: str
    config_digest: str
    status: ToolRunStatus
    planned_tests: int
    executed_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    report_digest: str | None
    error_summary: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ToolCaseResponse(BaseModel):
    id: str
    external_case_id: str
    outcome: ToolCaseOutcome
    score: float | None
    prompt: str | None
    response: str | None
    assertions: list[dict[str, Any]]
    created_at: datetime


class ToolRunDetailResponse(ToolRunResponse):
    cases: list[ToolCaseResponse]


class PromptfooClaimResponse(BaseModel):
    run_id: str
    provider: ToolTargetProvider
    endpoint: str
    model_name: str
    credential_environment_variable: str | None = None
    config: dict[str, Any]


class PromptfooCompletionRequest(BaseModel):
    tool_version: str = Field(min_length=1, max_length=80)
    report: dict[str, Any]


class PromptfooFailureRequest(BaseModel):
    error_summary: str = Field(min_length=1, max_length=1_000)
