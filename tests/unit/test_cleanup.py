import httpx
import respx

from oauthive.cleanup import revoke_session
from oauthive.client import OAuthClient
from oauthive.discovery import DiscoveryDoc
from oauthive.session import AuthSession

DOC = DiscoveryDoc.model_validate(
    {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "revocation_endpoint": "https://idp.example.com/revoke",
    }
)


@respx.mock
async def test_revoke_session_both_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("OAUTHIVE_HOME", str(tmp_path))
    respx.post("https://idp.example.com/revoke").mock(
        side_effect=[httpx.Response(200), httpx.Response(200)]
    )
    s = AuthSession(tenant_id="t", access_token="at", refresh_token="rt")
    s.save()
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="sec",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        report = await revoke_session(client, s)
    kinds = {o.token_kind: o.revoked for o in report.outcomes}
    assert kinds == {"refresh_token": True, "access_token": True}
    assert report.all_revoked is True
    # session file deleted
    assert AuthSession.load("t") is None


@respx.mock
async def test_revoke_session_partial_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("OAUTHIVE_HOME", str(tmp_path))
    respx.post("https://idp.example.com/revoke").mock(
        side_effect=[httpx.Response(200), httpx.Response(400)]
    )
    s = AuthSession(tenant_id="t", access_token="at", refresh_token="rt")
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="sec",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
        report = await revoke_session(client, s, delete_on_disk=False)
    assert report.all_revoked is False
    assert any(o.detail for o in report.outcomes if not o.revoked)
