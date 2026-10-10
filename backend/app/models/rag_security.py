from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SourceKind = Literal["staging_text", "document_extract", "connector_reference"]
RAGVerdict = Literal["approved", "quarantined"]
ReviewState = Literal[
    "auto_approved",
    "pending_review",
    "approved_exception",
    "rejected",
]


class RAGSourceInspectionRequest(BaseModel):
    system_id: str = Field(min_length=1, max_length=128)
    source_name: str = Field(min_length=1, max_length=255)
    source_kind: SourceKind = "staging_text"
    source_reference: str | None = Field(default=None, max_length=512)
    content: str = Field(min_length=1)

    @field_validator("source_name", "source_reference")
    @classmethod
    def strip_metadata(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Source metadata must not be empty.")
        return normalized


class RAGSecuritySignalResponse(BaseModel):
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


class RAGSourceResponse(BaseModel):
    id: str
    system_id: str
    source_name: str
    source_kind: SourceKind
    source_reference: str | None
    content_sha256: str
    content_characters: int
    verdict: RAGVerdict
    signals: list[RAGSecuritySignalResponse]
    recommendation: str
    review_state: ReviewState
    review_notes: str | None
    reviewed_at: datetime | None
    created_at: datetime


class RAGSourceSummary(BaseModel):
    total_sources: int
    eligible_for_indexing: int
    pending_review: int
    quarantined: int
    recent_sources: list[RAGSourceResponse] = Field(default_factory=list)


class RAGSourceReviewRequest(BaseModel):
    decision: Literal["keep_quarantined", "approve_exception"]
    notes: str = Field(min_length=10, max_length=1_000)
