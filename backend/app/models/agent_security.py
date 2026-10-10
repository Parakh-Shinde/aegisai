from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

ActionType = Literal[
    "browser_navigation",
    "http_request",
    "data_export",
    "file_operation",
    "connector_action",
    "shell_command",
    "other",
]
ActionVerdict = Literal["allowed", "quarantined", "blocked"]
ActionReviewState = Literal[
    "auto_approved",
    "pending_review",
    "approved_exception",
    "rejected",
]


class AgentActionInspectionRequest(BaseModel):
    system_id: str = Field(min_length=1, max_length=128)
    action_type: ActionType
    tool_name: str = Field(min_length=1, max_length=120)
    target: str | None = Field(default=None, max_length=512)
    arguments: dict[str, Any] = Field(default_factory=dict)
    page_excerpt: str | None = Field(default=None)

    @field_validator("tool_name", "target")
    @classmethod
    def strip_metadata(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Action metadata must not be empty.")
        return normalized


class AgentSecuritySignalResponse(BaseModel):
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


class AgentActionResponse(BaseModel):
    id: str
    system_id: str
    action_type: ActionType
    tool_name: str
    target: str | None
    request_sha256: str
    request_characters: int
    verdict: ActionVerdict
    signals: list[AgentSecuritySignalResponse]
    recommendation: str
    review_state: ActionReviewState
    review_notes: str | None
    reviewed_at: datetime | None
    created_at: datetime


class AgentActionSummary(BaseModel):
    total_actions: int
    allowed: int
    pending_review: int
    blocked: int
    recent_actions: list[AgentActionResponse] = Field(default_factory=list)


class AgentActionReviewRequest(BaseModel):
    decision: Literal["keep_quarantined", "approve_exception"]
    notes: str = Field(min_length=10, max_length=1_000)
