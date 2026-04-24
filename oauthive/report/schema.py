"""Versioned schema for findings.json.

schema_version=1: first stable surface. Subsequent breaking changes bump the
number and keep the loader able to render older reports via a migration step
in oauthive/report/html.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = 1

CheckStatus = Literal["pass", "fail", "error", "skipped"]


class FindingRecord(BaseModel):
    id: str
    severity: str
    confidence: str
    title: str
    description: str
    spec_ref: str
    remediation: str
    poc_url: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class CheckRecord(BaseModel):
    id: str
    name: str
    status: CheckStatus
    duration_s: float
    findings: list[FindingRecord] = Field(default_factory=list)
    error: str | None = None
    skip_reason: str | None = None


class RunMetadata(BaseModel):
    tenant_id: str
    started_at: datetime
    finished_at: datetime
    tool_version: str
    target_issuer: str | None = None
    allow_public_provider: bool = False
    allow_public_reason: str | None = None


class Report(BaseModel):
    schema_version: int = SCHEMA_VERSION
    metadata: RunMetadata
    checks: list[CheckRecord] = Field(default_factory=list)

    def findings(self) -> list[FindingRecord]:
        return [f for c in self.checks for f in c.findings]

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in self.findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
