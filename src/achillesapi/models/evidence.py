"""Structured, secret-conscious HTTP execution evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RequestEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResponseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    body_truncated: bool = False
    elapsed_ms: float


class ExecutionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: RequestEvidence
    response: ResponseEvidence | None = None
    error: str | None = None
    executed: bool = False
    notes: list[str] = Field(default_factory=list)


class AssessmentFinding(BaseModel):
    """A passive assessment observation; never a confirmed vulnerability by itself."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str = "hypothesis"
    endpoint: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str
    metadata: dict[str, Any] = Field(default_factory=dict)
