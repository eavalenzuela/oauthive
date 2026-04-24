"""Check interface and Finding type.

See PLAN.md §Check interface. The runner (later milestone) loads checks, gates
them on requires_capabilities, and respects parallel_safe + requires_fresh_auth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..context import Context

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


@dataclass
class Finding:
    id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    spec_ref: str
    remediation: str
    poc_url: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Check(Protocol):
    id: str
    name: str
    parallel_safe: bool
    requires_fresh_auth: bool
    requires_capabilities: frozenset[str]

    async def run(self, ctx: "Context") -> list[Finding]: ...
