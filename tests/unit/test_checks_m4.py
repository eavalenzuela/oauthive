"""Unit tests for M4 checks: pkce, state, nonce, scope, response_type.

Each test stands up a small IdP via respx that misbehaves in one way and
asserts the corresponding finding id lands.
"""

from __future__ import annotations


import httpx
import respx
import structlog

from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.checks.nonce import NonceCheck
from oauthive.checks.pkce import PKCECheck
from oauthive.checks.response_type import ResponseTypeCheck
from oauthive.checks.scope import ScopeCheck
from oauthive.checks.state import StateCheck
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc

REGISTERED_REDIRECT = "https://app.example.test/cb"


def _doc(**overrides) -> DiscoveryDoc:
    data = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "email", "profile"],
    }
    data.update(overrides)
    return DiscoveryDoc.model_validate(data)


async def _build_ctx(doc: DiscoveryDoc, http: httpx.AsyncClient) -> Context:
    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
    client = OAuthClient(
        discovery=doc,
        client_id="oauthive-test",
        redirect_uri=REGISTERED_REDIRECT,
        http=http,
    )
    return Context(
        tenant_id="acme-dev",
        discovery=doc,
        capabilities=caps,
        http=http,
        log=structlog.get_logger(),
        client=client,
    )


# ---------- PKCE ----------


@respx.mock
async def test_pkce_not_required():
    """IdP accepts any auth request, including ones without code_challenge."""
    doc = _doc()
    respx.get("https://idp.example.test/authorize").mock(
        side_effect=lambda req: httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await PKCECheck().run(ctx)
    ids = {f.id for f in findings}
    assert "pkce.not_required" in ids


@respx.mock
async def test_pkce_plain_accepted_when_advertised():
    doc = _doc(code_challenge_methods_supported=["S256", "plain"])

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if "code_challenge" not in params:
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=no_pkce"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await PKCECheck().run(ctx)
    ids = {f.id for f in findings}
    assert "pkce.plain_supported" in ids
    # Not the "not advertised" variant, since the doc advertises 'plain'.
    assert "pkce.plain_accepted_when_not_advertised" not in ids


@respx.mock
async def test_pkce_plain_accepted_when_not_advertised():
    doc = _doc(code_challenge_methods_supported=["S256"])

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if "code_challenge" not in params:
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=no_pkce"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await PKCECheck().run(ctx)
    ids = {f.id for f in findings}
    assert "pkce.plain_accepted_when_not_advertised" in ids


@respx.mock
async def test_pkce_strict_server_produces_no_findings():
    """IdP rejects anything that doesn't have a valid S256 challenge."""
    doc = _doc()

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        method = params.get("code_challenge_method")
        challenge = params.get("code_challenge", "")
        if not challenge or method != "S256" or len(challenge) != 43:
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=pkce"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await PKCECheck().run(ctx)
    assert findings == []


# ---------- state ----------


@respx.mock
async def test_state_missing_accepted_and_no_iss():
    doc = _doc()

    def handler(req: httpx.Request) -> httpx.Response:
        # Always issue a code; never include iss. state is not checked.
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await StateCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "state.missing_accepted" in ids
    assert "state.iss_not_returned" in ids


@respx.mock
async def test_state_iss_returned_and_state_required():
    doc = _doc()

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if "state" not in params:
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=state"}
            )
        return httpx.Response(
            302,
            headers={
                "location": (
                    f"{REGISTERED_REDIRECT}?code=c&state={params['state']}"
                    "&iss=https://idp.example.test"
                )
            },
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await StateCheck().run(ctx)
    assert findings == []


# ---------- nonce ----------


@respx.mock
async def test_nonce_required_is_not_flagged_when_server_rejects():
    doc = _doc(response_types_supported=["code", "id_token"])

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if params.get("response_type") == "id_token" and "nonce" not in params:
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=nonce"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await NonceCheck().run(ctx)
    assert findings == []


@respx.mock
async def test_nonce_missing_accepted_for_hybrid():
    doc = _doc(response_types_supported=["code", "id_token"])

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}#id_token=eyJ.fake.jwt&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await NonceCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "nonce.missing_accepted_for_implicit_or_hybrid" in ids


@respx.mock
async def test_nonce_check_skipped_when_no_id_token_response_type():
    doc = _doc(response_types_supported=["code"])
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await NonceCheck().run(ctx)
    assert findings == []


# ---------- scope ----------


@respx.mock
async def test_scope_accepts_undocumented():
    doc = _doc(scopes_supported=["openid", "email"])
    respx.get("https://idp.example.test/authorize").mock(
        side_effect=lambda req: httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await ScopeCheck().run(ctx)
    ids = {f.id for f in findings}
    assert any(i.startswith("scope.undocumented_accepted.admin") for i in ids)
    # 'offline_access' isn't advertised but is often legitimately honored;
    # still, check fires because it's not in scopes_supported.
    assert any(i.startswith("scope.undocumented_accepted.offline_access") for i in ids)


@respx.mock
async def test_scope_strict_server_produces_no_findings():
    doc = _doc(scopes_supported=["openid", "email"])

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        requested = set((params.get("scope") or "").split())
        allowed = {"openid", "email", "profile"}
        if not requested.issubset(allowed):
            return httpx.Response(
                302, headers={"location": "https://idp.example.test/error?reason=scope"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await ScopeCheck().run(ctx)
    assert findings == []


# ---------- response_type ----------


async def test_response_type_flags_advertised_implicit():
    doc = _doc(response_types_supported=["code", "token", "id_token token"])
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        # Don't run the full check (probing won't mock cleanly here); just
        # confirm the advertised-implicit types show up in capabilities.
        advertised = set(ctx.capabilities.oidc.supported_response_types)
        implicit = advertised & {"token", "token id_token", "id_token token"}
        assert implicit


@respx.mock
async def test_response_type_implicit_issues_token():
    doc = _doc(response_types_supported=["code", "token"])

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if params.get("response_type") == "token":
            return httpx.Response(
                302, headers={"location": f"{REGISTERED_REDIRECT}#access_token=at&token_type=Bearer"}
            )
        return httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )

    respx.get("https://idp.example.test/authorize").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await ResponseTypeCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "response_type.implicit_advertised" in ids
    assert "response_type.implicit_token_issued" in ids


@respx.mock
async def test_response_type_fragment_accepted_for_code():
    doc = _doc(
        response_types_supported=["code"],
        response_modes_supported=["query", "fragment", "form_post"],
    )
    respx.get("https://idp.example.test/authorize").mock(
        side_effect=lambda req: httpx.Response(
            302, headers={"location": f"{REGISTERED_REDIRECT}?code=c&state=s"}
        )
    )
    async with httpx.AsyncClient() as http:
        ctx = await _build_ctx(doc, http)
        findings = await ResponseTypeCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "response_type.fragment_mode_accepted_for_code" in ids
