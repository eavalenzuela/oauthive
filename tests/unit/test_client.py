import httpx
import pytest
import respx

from oauthive.client import (
    AuthorizationRequest,
    OAuthClient,
    build_authorization_url,
    send_authorization_request,
)
from oauthive.discovery import DiscoveryDoc


def _doc():
    return DiscoveryDoc.model_validate(
        {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
        }
    )


def test_build_authorization_url_has_required_params():
    req = AuthorizationRequest(
        client_id="c",
        redirect_uri="https://app.example.test/cb",
        state="fixed-state",
    )
    url = build_authorization_url("https://idp.example.com/authorize", req)
    assert "client_id=c" in url
    assert "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb" in url
    assert "state=fixed-state" in url
    assert "nonce=" in url  # openid scope triggers nonce


def test_url_appends_to_existing_query():
    req = AuthorizationRequest(client_id="c", redirect_uri="https://a/b")
    url = build_authorization_url("https://idp.example.com/authorize?foo=bar", req)
    assert "foo=bar" in url and "client_id=c" in url


@respx.mock
async def test_send_authorization_request_accepted_redirect():
    respx.get("https://idp.example.com/authorize").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://app.example.test/cb?code=abc&state=s"},
        )
    )
    async with httpx.AsyncClient() as c:
        resp = await send_authorization_request(
            c,
            "https://idp.example.com/authorize",
            AuthorizationRequest(client_id="c", redirect_uri="https://app.example.test/cb"),
        )
    assert resp.accepted_redirect is True
    assert resp.location_host == "app.example.test"


@respx.mock
async def test_send_authorization_request_rejected_stays_on_idp():
    respx.get("https://idp.example.com/authorize").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://idp.example.com/error?reason=bad_redirect_uri"},
        )
    )
    async with httpx.AsyncClient() as c:
        resp = await send_authorization_request(
            c,
            "https://idp.example.com/authorize",
            AuthorizationRequest(client_id="c", redirect_uri="https://app.example.test/cb"),
        )
    assert resp.accepted_redirect is False
    assert resp.location_host == "idp.example.com"


@respx.mock
async def test_send_authorization_request_html_error_page():
    respx.get("https://idp.example.com/authorize").mock(
        return_value=httpx.Response(400, text="<html>invalid redirect_uri</html>")
    )
    async with httpx.AsyncClient() as c:
        resp = await send_authorization_request(
            c,
            "https://idp.example.com/authorize",
            AuthorizationRequest(client_id="c", redirect_uri="https://app.example.test/cb"),
        )
    assert resp.accepted_redirect is False
    assert resp.status_code == 400


async def test_oauth_client_requires_authorization_endpoint():
    bad = DiscoveryDoc.model_validate(
        {"issuer": "https://idp.example.com", "token_endpoint": "https://idp.example.com/token"}
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(ValueError, match="authorization_endpoint"):
            OAuthClient(
                discovery=bad,
                client_id="c",
                redirect_uri="https://app.example.test/cb",
                http=http,
            )
