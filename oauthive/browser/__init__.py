"""Browser driver layer.

Three drivers are supported:

- manual    : prints the authorization URL, reads the callback URL back from
              stdin. No deps. Right for interactive dev.
- refresh   : bootstraps a single AuthSession via the manual driver (or
              playwright if configured), caches the refresh token, and mints
              access tokens by refresh for subsequent auth dances that don't
              require a fresh code/state/nonce.
- playwright: scripts the login in Chromium. Only available if the optional
              [browser] extra is installed; absent that, selecting it raises
              a friendly error.
"""

from __future__ import annotations

from .base import AuthResult, BrowserDriver, BrowserError
from .manual import ManualDriver
from .refresh import RefreshDriver

__all__ = [
    "AuthResult",
    "BrowserDriver",
    "BrowserError",
    "ManualDriver",
    "RefreshDriver",
    "build_driver",
]


def build_driver(mode: str, **kwargs) -> BrowserDriver:
    if mode == "manual":
        return ManualDriver(**kwargs)
    if mode == "refresh":
        return RefreshDriver(**kwargs)
    if mode == "playwright":
        try:
            from .playwright_driver import PlaywrightDriver
        except ImportError as e:
            raise BrowserError(
                "playwright driver requires the [browser] extra. Install with: "
                "pip install 'oauthive[browser]' && playwright install chromium"
            ) from e
        return PlaywrightDriver(**kwargs)
    raise BrowserError(f"unknown browser mode: {mode!r}")
