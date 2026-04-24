"""End-to-end: permissive IdP exhibits the full M4 misconfig battery."""

from __future__ import annotations

import httpx
import pytest
import respx
import structlog

from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import fetch_discovery
from oauthive.runner import RunnerConfig, run

DISCOVERY = {
    "issuer": "https://idp.example.test",
    "authorization_endpoint": "https://idp.example.test/authorize",
    "token_endpoint": "https://idp.example.test/token",
    "response_types_supported": ["code", "token", "id_token"],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256", "plain"],
    "scopes_supported": ["openid", "email", "profile"],
}
REGISTERED = "https://app.example.test/cb"


def _handler(request: httpx.Request) -> httpx.Response:
    """Permissive IdP: accepts pretty much anything, never rejects, never sends iss."""
    params = dict(request.url.params)
    response_type = params.get("response_type", "code")
    redirect_uri = params.get("redirect_uri", REGISTERED)
    # redirect_uri check's 'exact' candidate expects the registered URL back.
    # Anything host-matching the registered redirect is honored.
    parsed = httpx.URL(redirect_uri)
    if parsed.host != "app.example.test":
        return httpx.Response(
            302, headers={"location": "https://idp.example.test/error?reason=bad_redirect"}
        )
    if response_type == "token":
        return httpx.Response(
            302, headers={"location": f"{redirect_uri}#access_token=at&token_type=Bearer"}
        )
    if response_type == "id_token":
        return httpx.Response(
            302, headers={"location": f"{redirect_uri}#id_token=eyJ.fake.jwt&state=s"}
        )
    # Default: code flow. Echo the code and state but never include iss.
    q = f"code=c"
    if "state" in params:
        q += f"&state={params['state']}"
    return httpx.Response(302, headers={"location": f"{redirect_uri}?{q}"})


@respx.mock
async def test_m4_full_sweep():
    respx.get("https://idp.example.test/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=DISCOVERY)
    )
    respx.get("https://idp.example.test/authorize").mock(side_effect=_handler)

    doc = await fetch_discovery("https://idp.example.test/.well-known/openid-configuration")
    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))

    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=doc,
            client_id="oauthive-test",
            redirect_uri=REGISTERED,
            http=http,
        )
        ctx = Context(
            tenant_id="acme-dev",
            discovery=doc,
            capabilities=caps,
            http=http,
            log=structlog.get_logger(),
            client=client,
        )
        report = await run(
            ctx,
            RunnerConfig(
                tenant_id="acme-dev",
                enabled=["pkce", "state", "nonce", "scope", "response_type"],
                disabled=[],
                target_issuer=str(doc.issuer),
            ),
        )

    by_id = {c.id: c for c in report.checks}
    assert set(by_id.keys()) == {"pkce", "state", "nonce", "scope", "response_type"}
    all_findings = {f.id for c in report.checks for f in c.findings}

    # Expected hits from each check.
    assert "pkce.not_required" in all_findings
    assert "pkce.plain_supported" in all_findings
    assert "state.missing_accepted" in all_findings
    assert "state.iss_not_returned" in all_findings
    assert "nonce.missing_accepted_for_implicit_or_hybrid" in all_findings
    assert any(f.startswith("scope.undocumented_accepted.") for f in all_findings)
    assert "response_type.implicit_advertised" in all_findings
    assert "response_type.implicit_token_issued" in all_findings
    assert "response_type.fragment_mode_accepted_for_code" in all_findings

    # Sanity on severity counts: at least one high and at least one medium.
    counts = report.severity_counts()
    assert counts["high"] >= 2
    assert counts["medium"] >= 1
