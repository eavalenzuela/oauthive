"""OIDC discovery document fetch + parse.

RFC 8414 (OAuth Authorization Server Metadata) and OpenID Connect Discovery 1.0.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class DiscoveryDoc(BaseModel):
    """Parsed OIDC / OAuth 2.0 metadata document.

    Unknown fields are preserved so quirks modules can reach them.
    """

    model_config = ConfigDict(extra="allow")

    issuer: HttpUrl
    authorization_endpoint: HttpUrl | None = None
    token_endpoint: HttpUrl | None = None
    userinfo_endpoint: HttpUrl | None = None
    jwks_uri: HttpUrl | None = None
    registration_endpoint: HttpUrl | None = None
    revocation_endpoint: HttpUrl | None = None
    introspection_endpoint: HttpUrl | None = None
    end_session_endpoint: HttpUrl | None = None
    pushed_authorization_request_endpoint: HttpUrl | None = None

    scopes_supported: list[str] = Field(default_factory=list)
    response_types_supported: list[str] = Field(default_factory=list)
    response_modes_supported: list[str] = Field(default_factory=list)
    grant_types_supported: list[str] = Field(default_factory=list)
    subject_types_supported: list[str] = Field(default_factory=list)
    id_token_signing_alg_values_supported: list[str] = Field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = Field(default_factory=list)
    code_challenge_methods_supported: list[str] = Field(default_factory=list)
    require_pushed_authorization_requests: bool | None = None
    dpop_signing_alg_values_supported: list[str] = Field(default_factory=list)
    tls_client_certificate_bound_access_tokens: bool | None = None
    backchannel_logout_supported: bool | None = None


class DiscoveryError(RuntimeError):
    """Raised when discovery fails to fetch or parse."""


async def fetch_discovery(url: str, *, client: httpx.AsyncClient | None = None) -> DiscoveryDoc:
    """Fetch and parse an OIDC discovery document.

    Pass an existing httpx.AsyncClient to reuse connection pooling in a larger run;
    otherwise a short-lived client is created.
    """
    own_client = client is None
    c = client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    try:
        resp = await c.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as e:
        raise DiscoveryError(f"fetch failed: {e}") from e
    finally:
        if own_client:
            await c.aclose()

    if resp.status_code != 200:
        raise DiscoveryError(f"expected 200, got {resp.status_code} from {url}")

    try:
        data = resp.json()
    except ValueError as e:
        raise DiscoveryError(f"response was not JSON: {e}") from e

    try:
        return DiscoveryDoc.model_validate(data)
    except Exception as e:
        raise DiscoveryError(f"discovery doc failed validation: {e}") from e
