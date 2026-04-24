import io

import httpx
import pytest
import respx

from oauthive.browser import BrowserError, build_driver
from oauthive.browser.manual import ManualDriver, parse_callback
from oauthive.browser.refresh import RefreshDriver
from oauthive.client import OAuthClient
from oauthive.discovery import DiscoveryDoc
from oauthive.session import AuthSession


DOC = DiscoveryDoc.model_validate(
    {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
    }
)


def test_parse_callback_code_flow():
    r = parse_callback("https://app.example.test/cb?code=xyz&state=abc")
    assert r.code == "xyz"
    assert r.state == "abc"
    assert r.error is None


def test_parse_callback_error():
    r = parse_callback("https://app.example.test/cb?error=access_denied&error_description=nope")
    assert r.code is None
    assert r.error == "access_denied"
    assert r.error_description == "nope"


def test_parse_callback_fragment():
    r = parse_callback(
        "https://app.example.test/cb#id_token=jwt-here&state=s"
    )
    assert r.id_token == "jwt-here"
    assert r.state == "s"


async def test_manual_driver_reads_callback_from_stream():
    inp = io.StringIO("https://app.example.test/cb?code=xyz&state=abc\n")
    out = io.StringIO()
    d = ManualDriver(input_stream=inp, output_stream=out)
    r = await d.authorize(
        "https://idp.example.com/authorize?...",
        expected_redirect_uri="https://app.example.test/cb",
    )
    assert r.code == "xyz"


async def test_manual_driver_empty_input_raises():
    inp = io.StringIO("")
    out = io.StringIO()
    d = ManualDriver(input_stream=inp, output_stream=out)
    with pytest.raises(BrowserError):
        await d.authorize("x", expected_redirect_uri="y")


def test_build_driver_unknown_mode():
    with pytest.raises(BrowserError, match="unknown"):
        build_driver("nope")


def test_build_driver_playwright_without_extra(monkeypatch):
    # Simulate the extra not being installed by hiding the module.
    import sys

    monkeypatch.setitem(sys.modules, "playwright", None)
    with pytest.raises(BrowserError, match=r"\[browser\] extra"):
        build_driver("playwright")


@respx.mock
async def test_refresh_driver_bootstrap(tmp_path):
    respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "at",
                "refresh_token": "rt",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
    )
    scripted = ManualDriver(
        input_stream=io.StringIO(
            "https://app.example.test/cb?code=authcode&state=s\n"
        ),
        output_stream=io.StringIO(),
    )
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        rd = RefreshDriver(tenant_id="acme-dev", sub_driver=scripted, sessions_dir=tmp_path)
        session = await rd.bootstrap(client)
    assert session.refresh_token == "rt"
    assert (tmp_path / "acme-dev.json").exists()


@respx.mock
async def test_refresh_driver_uses_cache(tmp_path):
    # Pre-seed a valid session.
    pre = AuthSession(
        tenant_id="acme-dev",
        access_token="at",
        refresh_token="rt",
        expires_at=9_999_999_999.0,
    )
    pre.save(tmp_path)
    # If bootstrap hits the token endpoint, the test should fail (cache should
    # satisfy the call). We register no mock for /token; respx will 418 unmatched.
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        rd = RefreshDriver(tenant_id="acme-dev", sessions_dir=tmp_path)
        session = await rd.bootstrap(client)
    assert session.access_token == "at"


@respx.mock
async def test_refresh_driver_refreshes_expired_session(tmp_path):
    respx.post("https://idp.example.com/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "new-at", "token_type": "Bearer", "expires_in": 3600},
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
        expired = AuthSession(
            tenant_id="t",
            access_token="old",
            refresh_token="keep-me",
            expires_at=0.0,
        )
        rd = RefreshDriver(tenant_id="t", sessions_dir=tmp_path)
        refreshed = await rd.ensure_fresh_access_token(client, expired)
    assert refreshed.access_token == "new-at"
    # RT preserved when server didn't rotate
    assert refreshed.refresh_token == "keep-me"
