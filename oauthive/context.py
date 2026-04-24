"""Run-scoped Context passed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx
import structlog

from .capabilities import CapabilitiesReport
from .discovery import DiscoveryDoc


@dataclass
class Context:
    tenant_id: str
    discovery: DiscoveryDoc | None
    capabilities: CapabilitiesReport
    http: httpx.AsyncClient
    log: structlog.stdlib.BoundLogger
    session: Any = None
    client: Any = None
    malicious_rp: Any = None
    saml_metadata: Any = None
    config: Any = None
    # Lazy bootstrap. Checks that need a live AuthSession call
    # `await ctx.ensure_session()`. The runner populates session_factory
    # with a coroutine; if None, ensure_session returns None and the check
    # should downgrade its confidence or skip the session-dependent sub-probe.
    session_factory: Callable[..., Awaitable[Any]] | None = None

    async def ensure_session(self, *, scope: str = "openid", fresh: bool = False) -> Any:
        if self.session_factory is None:
            return None
        if self.session is not None and not fresh:
            return self.session
        self.session = await self.session_factory(scope=scope, fresh=fresh)
        return self.session
