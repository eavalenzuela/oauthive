"""Token cleanup: best-effort revocation at end of run or via `oauthive cleanup`.

Per PLAN.md: tokens are revoked by default; dynamic registrations are left in
place. Revocation failures are recorded in a cleanup_report block and never
escalated to findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .client import OAuthClient
from .session import AuthSession


@dataclass
class CleanupOutcome:
    token_kind: str
    revoked: bool
    detail: str | None = None


@dataclass
class CleanupReport:
    tenant_id: str
    outcomes: list[CleanupOutcome] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "outcomes": [
                {"token_kind": o.token_kind, "revoked": o.revoked, "detail": o.detail}
                for o in self.outcomes
            ],
        }

    @property
    def all_revoked(self) -> bool:
        return all(o.revoked for o in self.outcomes)


async def revoke_session(
    client: OAuthClient,
    session: AuthSession,
    *,
    delete_on_disk: bool = True,
) -> CleanupReport:
    """Revoke both access_token and refresh_token. Deletes on-disk session file
    if all revocations succeeded (or if the session file existed at all)."""
    report = CleanupReport(tenant_id=session.tenant_id)

    if session.refresh_token:
        ok = await client.revoke(session.refresh_token, token_type_hint="refresh_token")
        report.outcomes.append(
            CleanupOutcome(
                token_kind="refresh_token",
                revoked=ok,
                detail=None if ok else "revocation endpoint refused or unreachable",
            )
        )
    if session.access_token:
        ok = await client.revoke(session.access_token, token_type_hint="access_token")
        report.outcomes.append(
            CleanupOutcome(
                token_kind="access_token",
                revoked=ok,
                detail=None if ok else "revocation endpoint refused or unreachable",
            )
        )

    if delete_on_disk:
        AuthSession.delete(session.tenant_id)
    return report
