"""Run-scoped Context passed to every check.

Fields populated by later milestones (AuthSession, MaliciousRP) are held as
Optional[Any] for now so the type surface is stable while those modules are
built out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
    # Filled in by later milestones. Typed as Any so their modules own the type.
    session: Any = None
    client: Any = None
    malicious_rp: Any = None
    saml_metadata: Any = None
    config: Any = None
    # Callable that yields an AuthSession. In isolated mode, mints fresh
    # every call; in fast mode, returns the shared one (or a fresh one if the
    # check set requires_fresh_auth). Populated by the runner.
    session_factory: Any = None
