"""End-to-end test: fake IdP via respx, full runner, redirect_uri check."""

from __future__ import annotations

import json

import httpx
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
    "jwks_uri": "https://idp.example.test/jwks.json",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
}

REGISTERED = "https://app.example.test/cb"


def _fake_authorize(request: httpx.Request) -> httpx.Response:
    """Permissive IdP: accepts any redirect_uri whose host ends in app.example.test
    OR starts with it (substring match bug). Rejects everything else on its own domain."""
    redirect = request.url.params.get("redirect_uri", "")
    parsed = httpx.URL(redirect) if redirect else None
    host = parsed.host if parsed else ""

    buggy = (
        host == "app.example.test"
        or host.endswith(".app.example.test")
        or host.startswith("app.example.test")  # catches subdomain_append
    )
    if buggy:
        return httpx.Response(302, headers={"location": f"{redirect}?code=fake&state=s"})
    return httpx.Response(
        302, headers={"location": "https://idp.example.test/error?reason=bad_redirect"}
    )


@respx.mock
async def test_runner_against_fake_idp():
    respx.get("https://idp.example.test/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=DISCOVERY)
    )
    respx.get("https://idp.example.test/authorize").mock(side_effect=_fake_authorize)

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
                enabled=["redirect_uri"],
                disabled=[],
                target_issuer=str(doc.issuer),
            ),
        )

    rec = next(c for c in report.checks if c.id == "redirect_uri")
    assert rec.status == "fail"

    ids = {f.id for f in rec.findings}
    assert "redirect_uri.subdomain_append" in ids

    findings_json = json.loads(report.model_dump_json())
    assert findings_json["schema_version"] == 1
    assert findings_json["metadata"]["tenant_id"] == "acme-dev"
