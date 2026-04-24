"""Honest OAuth 2.0 client.

M2 only needs what the redirect_uri check uses: build an authorization URL
and send a non-interactive GET to the authorization endpoint, capturing how
the IdP reacted (did it 302 to the requested redirect_uri, or did it keep us
on its own domain with an error?). Token exchange and refresh land in M4 when
checks that mint tokens come online.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

import httpx

from .discovery import DiscoveryDoc


@dataclass
class AuthorizationRequest:
    client_id: str
    redirect_uri: str
    scope: str = "openid"
    response_type: str = "code"
    state: str | None = None
    nonce: str | None = None
    extra: dict[str, str] | None = None

    def to_params(self) -> dict[str, str]:
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": self.response_type,
            "scope": self.scope,
            "state": self.state or secrets.token_urlsafe(16),
        }
        if "id_token" in self.response_type or "openid" in self.scope.split():
            params["nonce"] = self.nonce or secrets.token_urlsafe(16)
        if self.extra:
            params.update(self.extra)
        return params


@dataclass
class AuthorizationResponse:
    """Classified result of a non-interactive GET to /authorize.

    redirect_target is the Location header host+path (if any), extracted so
    checks can decide whether the IdP was willing to send a user-agent to the
    requested redirect_uri.
    """

    status_code: int
    location: str | None
    location_host: str | None
    body_excerpt: str
    final_url: str
    accepted_redirect: bool  # True iff Location matches the requested redirect_uri host+path


def build_authorization_url(endpoint: str, req: AuthorizationRequest) -> str:
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{urlencode(req.to_params())}"


def _same_redirect(location: str, requested: str) -> bool:
    """A Location is considered 'accepted' if its scheme+host+path match the
    requested redirect_uri. Query / fragment may differ (the IdP appends
    code / state / error)."""
    try:
        a = urlparse(location)
        b = urlparse(requested)
    except ValueError:
        return False
    return (a.scheme, a.hostname, a.port, a.path) == (
        b.scheme,
        b.hostname,
        b.port,
        b.path,
    )


async def send_authorization_request(
    client: httpx.AsyncClient,
    endpoint: str,
    req: AuthorizationRequest,
) -> AuthorizationResponse:
    """Send a non-interactive GET, do NOT follow redirects, classify the response."""
    url = build_authorization_url(endpoint, req)
    resp = await client.get(url, follow_redirects=False)
    location = resp.headers.get("location")
    location_host = urlparse(location).hostname if location else None
    accepted = bool(location and _same_redirect(location, req.redirect_uri))
    body = resp.text[:512] if resp.content else ""
    return AuthorizationResponse(
        status_code=resp.status_code,
        location=location,
        location_host=location_host,
        body_excerpt=body,
        final_url=str(resp.url),
        accepted_redirect=accepted,
    )


class OAuthClient:
    """Thin wrapper bundling a discovery doc + client credentials + httpx session.

    Grows with later milestones (token exchange, refresh, PAR, DPoP). For M2
    only the authorization-endpoint probe is needed.
    """

    def __init__(
        self,
        discovery: DiscoveryDoc,
        client_id: str,
        redirect_uri: str,
        *,
        client_secret: str | None = None,
        http: httpx.AsyncClient | None = None,
    ):
        if discovery.authorization_endpoint is None:
            raise ValueError("discovery doc has no authorization_endpoint")
        self.discovery = discovery
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._http = http or httpx.AsyncClient(timeout=15.0)
        self._own_http = http is None

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    async def probe_authorization(
        self,
        *,
        redirect_uri: str | None = None,
        scope: str = "openid",
        response_type: str = "code",
        extra: dict[str, str] | None = None,
    ) -> AuthorizationResponse:
        req = AuthorizationRequest(
            client_id=self.client_id,
            redirect_uri=redirect_uri or self.redirect_uri,
            scope=scope,
            response_type=response_type,
            extra=extra,
        )
        return await send_authorization_request(
            self._http, str(self.discovery.authorization_endpoint), req
        )
