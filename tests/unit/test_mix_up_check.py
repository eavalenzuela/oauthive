import httpx
import respx
import structlog

from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.checks.mix_up import MixUpCheck
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc


def _doc(**overrides):
    base = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "registration_endpoint": "https://idp.example.test/register",
    }
    base.update(overrides)
    return DiscoveryDoc.model_validate(base)


async def _ctx(doc: DiscoveryDoc, http: httpx.AsyncClient) -> Context:
    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
    client = OAuthClient(
        discovery=doc, client_id="c", redirect_uri="https://app.example.test/cb", http=http
    )
    return Context(
        tenant_id="t",
        discovery=doc,
        capabilities=caps,
        http=http,
        log=structlog.get_logger(),
        client=client,
    )


async def test_mix_up_skipped_without_registration_endpoint():
    doc = _doc(registration_endpoint=None)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await MixUpCheck().run(ctx)
    assert findings == []


@respx.mock
async def test_mix_up_anonymous_registration_accepted():
    doc = _doc()
    respx.post("https://idp.example.test/register").mock(
        return_value=httpx.Response(
            201, json={"client_id": "attacker-allocated", "client_name": "x"}
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await MixUpCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "dynamic_registration.anonymous_accepted" in ids


@respx.mock
async def test_mix_up_jwks_uri_unvalidated():
    doc = _doc()

    def handler(req: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(req.content.decode())
        client_id = "anon-" + body["client_name"][-8:]
        if body.get("jwks_uri"):
            return httpx.Response(
                201,
                json={
                    "client_id": client_id,
                    "client_name": body["client_name"],
                    "jwks_uri": body["jwks_uri"],
                },
            )
        return httpx.Response(201, json={"client_id": client_id})

    respx.post("https://idp.example.test/register").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await MixUpCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "dynamic_registration.anonymous_accepted" in ids
    assert "dynamic_registration.jwks_uri_unvalidated" in ids


@respx.mock
async def test_mix_up_strict_server_no_findings():
    doc = _doc()
    respx.post("https://idp.example.test/register").mock(
        return_value=httpx.Response(401, json={"error": "initial_access_token_required"})
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await MixUpCheck().run(ctx)
    assert findings == []
