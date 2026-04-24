"""Unit tests for M6 checks: refresh_token, logout."""

from __future__ import annotations

import httpx
import pytest
import respx
import structlog

from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.checks.logout import LogoutCheck
from oauthive.checks.refresh_token import RefreshTokenCheck
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc
from oauthive.session import AuthSession

REDIRECT = "https://app.example.test/cb"


def _doc(**overrides) -> DiscoveryDoc:
    base = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "end_session_endpoint": "https://idp.example.test/logout",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    base.update(overrides)
    return DiscoveryDoc.model_validate(base)


async def _ctx(doc: DiscoveryDoc, http: httpx.AsyncClient) -> Context:
    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
    client = OAuthClient(
        discovery=doc,
        client_id="oauthive-test",
        client_secret="s",
        redirect_uri=REDIRECT,
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


# ---------- refresh_token ----------


async def test_refresh_grant_not_advertised():
    doc = _doc(grant_types_supported=["authorization_code"])
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await RefreshTokenCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "refresh_token.grant_not_supported" in ids


async def test_refresh_no_session_no_dynamic_findings():
    doc = _doc()
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        # No session_factory -> ensure_session returns None -> dynamic probes skip.
        findings = await RefreshTokenCheck().run(ctx)
    assert findings == []


@respx.mock
async def test_refresh_rotation_not_enforced():
    doc = _doc()

    calls: list[dict] = []

    def token_handler(req: httpx.Request) -> httpx.Response:
        body = req.content.decode()
        calls.append({"body": body})
        # Always accept, issue the same refresh_token back.
        return httpx.Response(
            200,
            json={
                "access_token": f"at-{len(calls)}",
                "refresh_token": "reused-rt" if len(calls) > 1 else "initial-rt",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

    respx.post("https://idp.example.test/token").mock(side_effect=token_handler)

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        ctx.session = AuthSession(
            tenant_id="t", access_token="at", refresh_token="initial-rt"
        )

        async def factory(*, scope: str = "openid", fresh: bool = False):
            return ctx.session

        ctx.session_factory = factory
        findings = await RefreshTokenCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "refresh_token.rotation_not_enforced" in ids
    # Called token endpoint twice: once with initial-rt, once with initial-rt again.
    assert len(calls) == 2
    assert all("initial-rt" in c["body"] for c in calls)


@respx.mock
async def test_refresh_rotation_enforced_no_finding():
    doc = _doc()
    state = {"used": False}

    def token_handler(req: httpx.Request) -> httpx.Response:
        body = req.content.decode()
        if "refresh_token=initial-rt" in body:
            if state["used"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            state["used"] = True
            return httpx.Response(
                200,
                json={
                    "access_token": "at2",
                    "refresh_token": "new-rt",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        return httpx.Response(400, json={"error": "invalid_grant"})

    respx.post("https://idp.example.test/token").mock(side_effect=token_handler)

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        ctx.session = AuthSession(
            tenant_id="t", access_token="at", refresh_token="initial-rt"
        )

        async def factory(*, scope: str = "openid", fresh: bool = False):
            return ctx.session

        ctx.session_factory = factory
        findings = await RefreshTokenCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "refresh_token.rotation_not_enforced" not in ids


@respx.mock
async def test_refresh_cross_client_binding_weak():
    doc = _doc()
    state = {"used": False}

    def token_handler(req: httpx.Request) -> httpx.Response:
        body = req.content.decode()
        # Allow every call.
        return httpx.Response(
            200,
            json={
                "access_token": "at",
                "refresh_token": "rt-x",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

    respx.post("https://idp.example.test/token").mock(side_effect=token_handler)

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        ctx.session = AuthSession(
            tenant_id="t", access_token="at", refresh_token="primary-rt"
        )

        async def factory(*, scope: str = "openid", fresh: bool = False):
            return ctx.session

        ctx.session_factory = factory
        ctx.secondary_client = OAuthClient(
            discovery=doc,
            client_id="other-client",
            client_secret="s2",
            redirect_uri="https://other.example.test/cb",
            http=http,
        )
        findings = await RefreshTokenCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "refresh_token.binding_to_client_weak" in ids


# ---------- logout ----------


async def test_logout_no_end_session_endpoint():
    doc = _doc()
    doc.end_session_endpoint = None
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await LogoutCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "logout.no_end_session_endpoint" in ids


@respx.mock
async def test_logout_no_id_token_hint_required_and_open_redirect():
    doc = _doc()
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        post_logout = dict(req.url.params).get("post_logout_redirect_uri", "/")
        return httpx.Response(302, headers={"location": post_logout})

    respx.get("https://idp.example.test/logout").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await LogoutCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "logout.no_id_token_hint_required" in ids
    assert "logout.post_logout_redirect_open" in ids


@respx.mock
async def test_logout_strict_server_no_findings():
    doc = _doc()

    def handler(req: httpx.Request) -> httpx.Response:
        params = dict(req.url.params)
        if "id_token_hint" not in params:
            return httpx.Response(400, text="id_token_hint required")
        post_logout = params.get("post_logout_redirect_uri", "/")
        if "evil.example.test" in post_logout:
            return httpx.Response(400, text="bad post_logout_redirect_uri")
        return httpx.Response(302, headers={"location": post_logout})

    respx.get("https://idp.example.test/logout").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await LogoutCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "logout.no_id_token_hint_required" not in ids
    assert "logout.post_logout_redirect_open" not in ids


@respx.mock
async def test_logout_no_session_notification_channel():
    doc = _doc()  # neither backchannel_logout_supported nor frontchannel_logout_supported
    # Strict server: rejects all logout probes. We only care about the
    # discovery-derived finding here.
    respx.get("https://idp.example.test/logout").mock(return_value=httpx.Response(400))
    async with httpx.AsyncClient() as http:
        ctx = await _ctx(doc, http)
        findings = await LogoutCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "logout.no_session_notification" in ids
