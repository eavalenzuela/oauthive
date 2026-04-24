import httpx
import pytest
import respx

from oauthive.discovery import DiscoveryError, fetch_discovery

SAMPLE = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "jwks_uri": "https://idp.example.com/jwks.json",
    "response_types_supported": ["code", "code id_token"],
    "response_modes_supported": ["query", "form_post"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "id_token_signing_alg_values_supported": ["RS256", "ES256"],
    "code_challenge_methods_supported": ["S256"],
    "end_session_endpoint": "https://idp.example.com/logout",
    "pushed_authorization_request_endpoint": "https://idp.example.com/par",
}


@respx.mock
async def test_fetch_discovery_happy_path():
    respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=SAMPLE)
    )
    doc = await fetch_discovery("https://idp.example.com/.well-known/openid-configuration")
    assert str(doc.issuer).rstrip("/") == "https://idp.example.com"
    assert "S256" in doc.code_challenge_methods_supported
    assert doc.end_session_endpoint is not None


@respx.mock
async def test_fetch_discovery_non_200():
    respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(404, text="nope")
    )
    with pytest.raises(DiscoveryError, match="404"):
        await fetch_discovery("https://idp.example.com/.well-known/openid-configuration")


@respx.mock
async def test_fetch_discovery_not_json():
    respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, text="<html>not json</html>")
    )
    with pytest.raises(DiscoveryError, match="not JSON"):
        await fetch_discovery("https://idp.example.com/.well-known/openid-configuration")


@respx.mock
async def test_fetch_discovery_missing_issuer():
    respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json={"token_endpoint": "https://idp.example.com/token"})
    )
    with pytest.raises(DiscoveryError, match="validation"):
        await fetch_discovery("https://idp.example.com/.well-known/openid-configuration")
