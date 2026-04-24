"""Refresh driver: bootstrap once, then mint ATs by refresh.

Flow:
  1. On first call (or if cache miss / RT expired): delegate to a sub-driver
     (default ManualDriver) to walk the full code flow, exchange for tokens,
     persist.
  2. On subsequent calls: if the check doesn't need a fresh code/state/nonce,
     mint a new AT from the cached RT.

The runner owns the decision about which checks can be served by the cached
RT -- drivers only do what they're asked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..client import OAuthClient, generate_pkce_pair
from ..session import AuthSession
from .base import AuthResult, BrowserDriver, BrowserError
from .manual import ManualDriver


@dataclass
class RefreshDriver(BrowserDriver):
    """Wraps a sub-driver (usually ManualDriver) and caches the resulting session."""

    tenant_id: str = ""
    sub_driver: BrowserDriver = field(default_factory=ManualDriver)
    sessions_dir: Path | None = None

    async def authorize(self, url: str, *, expected_redirect_uri: str) -> AuthResult:
        return await self.sub_driver.authorize(url, expected_redirect_uri=expected_redirect_uri)

    async def bootstrap(self, client: OAuthClient, *, scope: str = "openid") -> AuthSession:
        """One-time: walk the full code flow, exchange, persist. Returns the session.

        Idempotent: if a valid cached session exists, returns it without a new
        auth dance.
        """
        cached = AuthSession.load(self.tenant_id, self.sessions_dir)
        if cached and cached.refresh_token and not cached.is_expired():
            return cached

        verifier, challenge = generate_pkce_pair()
        from ..client import AuthorizationRequest, build_authorization_url

        req = AuthorizationRequest(
            client_id=client.client_id,
            redirect_uri=client.redirect_uri,
            scope=scope,
            response_type="code",
            extra={"code_challenge": challenge, "code_challenge_method": "S256"},
        )
        auth_url = build_authorization_url(
            str(client.discovery.authorization_endpoint), req
        )
        result = await self.sub_driver.authorize(
            auth_url, expected_redirect_uri=client.redirect_uri
        )
        if result.error or not result.code:
            raise BrowserError(
                f"authorization failed: error={result.error!r} "
                f"description={result.error_description!r}"
            )
        session = await client.exchange_code(
            result.code,
            code_verifier=verifier,
            tenant_id=self.tenant_id,
        )
        session.save(self.sessions_dir)
        return session

    async def ensure_fresh_access_token(
        self, client: OAuthClient, session: AuthSession
    ) -> AuthSession:
        """Refresh the AT if near expiry, update cache. Returns a valid session.

        If refresh fails the caller should bootstrap again.
        """
        if not session.is_expired() and session.access_token:
            return session
        if not session.refresh_token:
            raise BrowserError("no refresh_token available; re-run bootstrap")
        refreshed = await client.refresh(session.refresh_token, tenant_id=self.tenant_id)
        # Preserve the RT if the server didn't rotate it.
        if not refreshed.refresh_token:
            refreshed.refresh_token = session.refresh_token
        refreshed.save(self.sessions_dir)
        return refreshed
