from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class FileSecuritySignalResponse(BaseModel):
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


class FileSecurityScanResponse(BaseModel):
    id: str
    system_id: str | None
    filename: str
    declared_content_type: str | None
    detected_type: str
    sha256: str
    file_size_bytes: int
    verdict: Literal["allowed", "quarantined", "blocked"]
    signals: list[FileSecuritySignalResponse]
    recommendation: str
    created_at: datetime


class FileSecurityScanSummary(BaseModel):
    total_scans: int
    allowed: int
    quarantined: int
    blocked: int
    recent_scans: list[FileSecurityScanResponse] = Field(default_factory=list)
