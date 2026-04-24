"""AuthSession: token bundle plus disk persistence.

A run may share an AuthSession across checks (fast mode) or mint a fresh one
per check (isolated mode). On disk the session lives at
  ~/.oauthive/sessions/<tenant-id>.json
with mode 0600. Callers are responsible for calling save() after mutating
tokens and for revoke() (via OAuthClient) at end-of-run unless --no-cleanup.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def default_sessions_dir() -> Path:
    return Path(os.environ.get("OAUTHIVE_HOME", Path.home() / ".oauthive")) / "sessions"


@dataclass
class AuthSession:
    tenant_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    token_type: str = "Bearer"
    scope: str | None = None
    # Unix epoch seconds; None = unknown.
    expires_at: float | None = None
    # Arbitrary extra data returned by the token endpoint (e.g. iss, nonce).
    extra: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, *, leeway_s: float = 30.0) -> bool:
        if self.expires_at is None:
            return False
        return time.time() + leeway_s >= self.expires_at

    @classmethod
    def from_token_response(cls, tenant_id: str, data: dict[str, Any]) -> "AuthSession":
        """Build from an OAuth token response body (RFC 6749 sec 5.1)."""
        expires_at: float | None = None
        if "expires_in" in data:
            try:
                expires_at = time.time() + float(data["expires_in"])
            except (TypeError, ValueError):
                expires_at = None
        known = {"access_token", "refresh_token", "id_token", "token_type", "scope", "expires_in"}
        extra = {k: v for k, v in data.items() if k not in known}
        return cls(
            tenant_id=tenant_id,
            access_token=data.get("access_token"),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            token_type=data.get("token_type", "Bearer"),
            scope=data.get("scope"),
            expires_at=expires_at,
            extra=extra,
        )

    def path(self, base: Path | None = None) -> Path:
        base = base or default_sessions_dir()
        return base / f"{self.tenant_id}.json"

    def save(self, base: Path | None = None) -> Path:
        p = self.path(base)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, default=str))
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, p)
        return p

    @classmethod
    def load(cls, tenant_id: str, base: Path | None = None) -> "AuthSession | None":
        p = (base or default_sessions_dir()) / f"{tenant_id}.json"
        if not p.exists():
            return None
        data = json.loads(p.read_text())
        data.pop("tenant_id", None)
        return cls(tenant_id=tenant_id, **data)

    @classmethod
    def delete(cls, tenant_id: str, base: Path | None = None) -> bool:
        p = (base or default_sessions_dir()) / f"{tenant_id}.json"
        if p.exists():
            p.unlink()
            return True
        return False

    def redacted(self) -> dict[str, Any]:
        """For logging / evidence: keep prefix+suffix, redact middle."""
        def _r(v: str | None) -> str | None:
            if not v:
                return v
            if len(v) <= 12:
                return "***"
            return f"{v[:6]}...{v[-4:]}"

        return {
            "tenant_id": self.tenant_id,
            "access_token": _r(self.access_token),
            "refresh_token": _r(self.refresh_token),
            "id_token": _r(self.id_token),
            "token_type": self.token_type,
            "scope": self.scope,
            "expires_at": self.expires_at,
        }
