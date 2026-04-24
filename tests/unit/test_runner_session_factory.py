"""Tests for the runner's session_factory wiring."""

from __future__ import annotations

import httpx
import structlog

from oauthive.capabilities import CapabilitiesReport, OIDCCapabilities
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc
from oauthive.runner import RunnerConfig, run
from oauthive.session import AuthSession


DOC = DiscoveryDoc.model_validate(
    {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
    }
)


class _StubDriver:
    def __init__(self, *, session: AuthSession | None = None, raises: Exception | None = None):
        self._session = session
        self._raises = raises
        self.calls = 0

    async def bootstrap(self, client, *, scope: str = "openid") -> AuthSession:
        self.calls += 1
        if self._raises:
            raise self._raises
        return self._session  # type: ignore[return-value]


class _CapturingCheck:
    id = "capture"
    name = "capture"
    parallel_safe = False
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    def __init__(self):
        self.seen_session: AuthSession | None = None

    async def run(self, ctx):
        self.seen_session = await ctx.ensure_session()
        return []


async def _ctx(http: httpx.AsyncClient) -> Context:
    return Context(
        tenant_id="t",
        discovery=DOC,
        capabilities=CapabilitiesReport(oidc=OIDCCapabilities(present=True)),
        http=http,
        log=structlog.get_logger(),
        client=OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
        ),
    )


async def test_session_factory_bootstraps_via_driver(monkeypatch):
    sess = AuthSession(tenant_id="t", access_token="at", refresh_token="rt")
    driver = _StubDriver(session=sess)
    captured = _CapturingCheck()
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [captured])

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(http)
        await run(
            ctx,
            RunnerConfig(tenant_id="t", enabled=["all"], disabled=[], driver=driver),
        )
    assert driver.calls == 1
    assert captured.seen_session is sess


async def test_session_factory_caches_result(monkeypatch):
    sess = AuthSession(tenant_id="t", access_token="at")
    driver = _StubDriver(session=sess)

    class _TwiceCheck:
        id = "twice"
        name = "twice"
        parallel_safe = False
        requires_fresh_auth = False
        requires_capabilities = frozenset({"oidc"})

        async def run(self, ctx):
            a = await ctx.ensure_session()
            b = await ctx.ensure_session()
            assert a is b
            return []

    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [_TwiceCheck()])

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(http)
        await run(
            ctx,
            RunnerConfig(tenant_id="t", enabled=["all"], disabled=[], driver=driver),
        )
    assert driver.calls == 1


async def test_session_factory_swallows_bootstrap_errors(monkeypatch):
    driver = _StubDriver(raises=RuntimeError("boom"))
    captured = _CapturingCheck()
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [captured])

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(http)
        report = await run(
            ctx,
            RunnerConfig(tenant_id="t", enabled=["all"], disabled=[], driver=driver),
        )
    # Capturing check saw None, but the run itself did not fail.
    assert captured.seen_session is None
    assert report.checks[0].status == "pass"


async def test_no_driver_means_no_session(monkeypatch):
    captured = _CapturingCheck()
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [captured])

    async with httpx.AsyncClient() as http:
        ctx = await _ctx(http)
        await run(
            ctx,
            RunnerConfig(tenant_id="t", enabled=["all"], disabled=[], driver=None),
        )
    assert captured.seen_session is None
