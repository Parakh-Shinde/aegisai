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
EnforcementDecision = Literal["allow", "require_review", "deny"]


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


class AgentEnforcementResponse(BaseModel):
    action: AgentActionResponse
    decision: EnforcementDecision
    execution_permitted: bool
    enforcement_mode: Literal["enforce", "observe"]
    idempotent_replay: bool = False


class AgentRuntimeEvaluationRequest(BaseModel):
    system_id: str = Field(min_length=1, max_length=128)


class AgentRuntimeEvaluationCaseResponse(BaseModel):
    test_id: str
    action_id: str
    expected_verdict: ActionVerdict
    actual_verdict: ActionVerdict
    passed: bool
    signals: list[AgentSecuritySignalResponse]


class MeasurementValueResponse(BaseModel):
    value: float | None
    status: Literal["available", "unavailable"]
    denominator: int | None = None
    reason: str | None = None


class AgentRuntimeMetricsResponse(BaseModel):
    planned_tests: int
    executed_tests: int
    skipped_tests: int
    unsupported_tests: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    test_execution_rate_percent: MeasurementValueResponse
    applicable_test_coverage_percent: MeasurementValueResponse
    detection_precision_percent: MeasurementValueResponse
    detection_recall_percent: MeasurementValueResponse
    false_positive_rate_percent: MeasurementValueResponse
    evaluation_engine_reliability_percent: MeasurementValueResponse
    tool_reliability_percent: MeasurementValueResponse
    mean_time_to_detect_ms: MeasurementValueResponse
    assessment_duration_ms: MeasurementValueResponse
    resource_consumption: MeasurementValueResponse
    remediation_success_rate_percent: MeasurementValueResponse
    regression_rate_percent: MeasurementValueResponse


class AgentRuntimeEvaluationResponse(BaseModel):
    run_id: str
    system_id: str
    suite_name: str
    corpus_version: str
    corpus_digest: str
    scoring_rule_version: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    evaluation_status: Literal["passed", "failed"]
    metrics: AgentRuntimeMetricsResponse
    cases: list[AgentRuntimeEvaluationCaseResponse]


class AgentActionSummary(BaseModel):
    total_actions: int
    allowed: int
    pending_review: int
    blocked: int
    recent_actions: list[AgentActionResponse] = Field(default_factory=list)


class AgentActionReviewRequest(BaseModel):
    decision: Literal["keep_quarantined", "approve_exception"]
    notes: str = Field(min_length=10, max_length=1_000)
