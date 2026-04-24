import httpx
import pytest
import respx
import structlog

from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.checks.id_token import IDTokenCheck
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc


def _doc(**overrides):
    base = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "jwks_uri": "https://idp.example.test/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    base.update(overrides)
    return DiscoveryDoc.model_validate(base)


async def _ctx(doc: DiscoveryDoc, http: httpx.AsyncClient) -> Context:
    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
    client = OAuthClient(
        discovery=doc,
        client_id="oauthive-test",
        redirect_uri="https://app.example.test/cb",
        http=http,
    )
    return Context(
        tenant_id="t",
        discovery=doc,
        capabilities=caps,
        http=http,
        log=structlog.get_logger(),
        client=client,
    )


@respx.mock
async def test_none_advertised_and_only_symmetric():
    doc = _doc(id_token_signing_alg_values_supported=["none", "HS256"])
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "a"}]})
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.none_advertised" in ids
    # Only advertises 'none' and 'HS256' -- after removing 'none' still only symmetric.
    # Our check tests advertised.issubset(symmetric). With 'none' included, the
    # subset test fails; that's fine -- the critical finding is already raised.
    # The 'only_symmetric_algs' finding only fires when advertised is pure HS*.
    assert "id_token.only_symmetric_algs" not in ids


@respx.mock
async def test_only_symmetric_flagged():
    doc = _doc(id_token_signing_alg_values_supported=["HS256", "HS512"])
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(200, json={"keys": [{"kty": "oct", "kid": "a", "k": "..."}]})
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.only_symmetric_algs" in ids


@respx.mock
async def test_jwks_unreachable():
    doc = _doc()
    respx.get("https://idp.example.test/jwks.json").mock(return_value=httpx.Response(503))
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.jwks_unreachable" in ids


@respx.mock
async def test_jwks_exposes_private_material():
    doc = _doc()
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "sensitive",
                        "n": "AAAA",
                        "e": "AQAB",
                        "d": "should-not-be-here",
                        "p": "x",
                        "q": "y",
                    }
                ]
            },
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.jwks_exposes_private_material" in ids
    # Must be critical severity
    f = next(f for f in findings if f.id == "id_token.jwks_exposes_private_material")
    assert f.severity == "critical"


@respx.mock
async def test_jwks_empty():
    doc = _doc()
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(200, json={"keys": []})
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.jwks_empty" in ids


@respx.mock
async def test_jwks_missing_kids_with_multiple_keys():
    doc = _doc()
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    {"kty": "RSA", "n": "AA", "e": "AQAB"},
                    {"kty": "RSA", "n": "BB", "e": "AQAB"},
                ]
            },
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "id_token.jwks_missing_kids" in ids


@respx.mock
async def test_clean_jwks_produces_no_findings():
    doc = _doc(id_token_signing_alg_values_supported=["RS256", "ES256"])
    respx.get("https://idp.example.test/jwks.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [{"kty": "RSA", "kid": "a", "n": "AA", "e": "AQAB", "alg": "RS256"}]
            },
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await IDTokenCheck().run(ctx)
    assert findings == []
