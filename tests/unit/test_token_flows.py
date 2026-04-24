import base64

import httpx
import pytest
import respx

from oauthive.client import (
    OAuthClient,
    TokenError,
    generate_pkce_pair,
)
from oauthive.discovery import DiscoveryDoc

DOC = DiscoveryDoc.model_validate(
    {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "revocation_endpoint": "https://idp.example.com/revoke",
    }
)


def test_pkce_pair_is_s256():
    import hashlib

    v, c = generate_pkce_pair()
    digest = hashlib.sha256(v.encode()).digest()
    expected = (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    )
    assert c == expected


@respx.mock
async def test_exchange_code_happy():
    route = respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "at",
                "refresh_token": "rt",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid",
            },
        )
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        session = await client.exchange_code(
            "auth-code",
            code_verifier="verifier",
            tenant_id="acme-dev",
        )
    assert session.access_token == "at"
    assert session.refresh_token == "rt"
    assert route.called
    call = route.calls.last.request
    # Basic auth header for client_secret_basic
    assert call.headers["authorization"].startswith("Basic ")
    body = dict(x.split("=", 1) for x in call.content.decode().split("&"))
    assert body["code"] == "auth-code"
    assert body["code_verifier"] == "verifier"
    assert body["grant_type"] == "authorization_code"


@respx.mock
async def test_exchange_code_public_client_no_basic_auth():
    route = respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "at", "token_type": "Bearer"})
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret=None,
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        await client.exchange_code("x", tenant_id="t")
    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers.keys()}


@respx.mock
async def test_exchange_code_error_raises_token_error():
    respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        with pytest.raises(TokenError) as exc:
            await client.exchange_code("x")
    assert exc.value.status_code == 400
    assert exc.value.body == {"error": "invalid_grant"}


@respx.mock
async def test_refresh_flow():
    respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "at2", "refresh_token": "rt2", "token_type": "Bearer", "expires_in": 600},
        )
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        session = await client.refresh("old-rt", scope="openid email")
    assert session.access_token == "at2"
    assert session.refresh_token == "rt2"


@respx.mock
async def test_revoke_success_and_failure():
    respx.post("https://idp.example.com/revoke").mock(
        side_effect=[httpx.Response(200), httpx.Response(400)]
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        assert await client.revoke("some-token", "access_token") is True
        assert await client.revoke("other-token", "refresh_token") is False


async def test_revoke_without_endpoint_returns_false():
    no_revoke = DiscoveryDoc.model_validate(
        {
            "issuer": "https://idp.example.com",
            "token_endpoint": "https://idp.example.com/token",
            "authorization_endpoint": "https://idp.example.com/authorize",
        }
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=no_revoke,
            client_id="c",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        assert await client.revoke("tok") is False
