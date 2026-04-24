"""BrowserDriver protocol and shared types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class BrowserError(RuntimeError):
    """Raised by drivers on any unrecoverable interaction failure."""


@dataclass
class AuthResult:
    """Result of driving a single authorization flow to the callback.

    code and state are parsed out of the callback URL when present; id_token
    is present in hybrid / implicit flows.
    """

    callback_url: str
    code: str | None = None
    state: str | None = None
    id_token: str | None = None
    error: str | None = None
    error_description: str | None = None


@runtime_checkable
class BrowserDriver(Protocol):
    async def authorize(self, url: str, *, expected_redirect_uri: str) -> AuthResult:
        """Navigate the user through the auth URL; return the callback."""
