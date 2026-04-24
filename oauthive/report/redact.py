"""Evidence redaction helpers.

Walks arbitrary structures (dicts / lists / strings) and replaces anything
that looks like a JWT or a long opaque credential with a shortened form that
preserves traceability (prefix + sha8 + suffix).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")
_LONG_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-\.]{40,}$")

_SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "client_secret",
    "code",
    "code_verifier",
    "assertion",
}


def _redact_value(v: str) -> str:
    digest = hashlib.sha256(v.encode()).hexdigest()[:8]
    if len(v) > 16:
        return f"{v[:6]}...<{digest}>...{v[-4:]}"
    return f"<redacted:{digest}>"


def redact(obj: Any, *, path: tuple[str, ...] = ()) -> Any:
    """Return a copy of obj with sensitive-looking strings redacted.

    - Dict keys in _SENSITIVE_KEYS always redact their value (if string).
    - String values matching a JWT or a long opaque credential redact.
    - Other values pass through.
    """
    if isinstance(obj, dict):
        return {k: redact(v, path=path + (str(k),)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x, path=path) for x in obj]
    if isinstance(obj, str):
        tail = path[-1] if path else ""
        if tail in _SENSITIVE_KEYS or _JWT_RE.match(obj) or _LONG_TOKEN_RE.match(obj):
            return _redact_value(obj)
        return obj
    return obj
