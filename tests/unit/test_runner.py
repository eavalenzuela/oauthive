from dataclasses import dataclass

import httpx
import pytest
import structlog

from oauthive.capabilities import CapabilitiesReport, OIDCCapabilities
from oauthive.checks.base import Finding
from oauthive.context import Context
from oauthive.runner import RunnerConfig, _discover_checks, run, select_checks


@dataclass
class _FakeCheck:
    id: str
    name: str
    parallel_safe: bool = True
    requires_fresh_auth: bool = False
    requires_capabilities: frozenset = frozenset()
    should_raise: bool = False
    findings: list = None

    async def run(self, ctx):
        if self.should_raise:
            raise RuntimeError("boom")
        return self.findings or []


def test_select_all():
    checks = [_FakeCheck(id="a", name="A"), _FakeCheck(id="b", name="B")]
    out = select_checks(checks, ["all"], [])
    assert [c.id for c in out] == ["a", "b"]


def test_select_subset_and_disabled():
    checks = [
        _FakeCheck(id="a", name="A"),
        _FakeCheck(id="b", name="B"),
        _FakeCheck(id="c", name="C"),
    ]
    out = select_checks(checks, ["a", "b"], ["b"])
    assert [c.id for c in out] == ["a"]


def test_discover_checks_finds_redirect_uri():
    ids = {c.id for c in _discover_checks()}
    assert "redirect_uri" in ids


async def _ctx(caps: CapabilitiesReport) -> Context:
    return Context(
        tenant_id="t",
        discovery=None,
        capabilities=caps,
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
    )


async def test_run_skips_checks_missing_capabilities(monkeypatch):
    check = _FakeCheck(
        id="needs_saml",
        name="needs_saml",
        requires_capabilities=frozenset({"saml"}),
    )
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [check])
    ctx = await _ctx(CapabilitiesReport(oidc=OIDCCapabilities(present=True)))
    cfg = RunnerConfig(tenant_id="t", enabled=["all"], disabled=[])
    report = await run(ctx, cfg)
    assert report.checks[0].status == "skipped"
    assert "saml" in report.checks[0].skip_reason


async def test_run_catches_check_exceptions(monkeypatch):
    check = _FakeCheck(id="breaks", name="breaks", should_raise=True)
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [check])
    ctx = await _ctx(CapabilitiesReport(oidc=OIDCCapabilities(present=True)))
    report = await run(ctx, RunnerConfig(tenant_id="t", enabled=["all"], disabled=[]))
    assert report.checks[0].status == "error"
    assert "RuntimeError" in report.checks[0].error


async def test_run_pass_when_no_findings(monkeypatch):
    check = _FakeCheck(id="ok", name="ok", findings=[])
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [check])
    ctx = await _ctx(CapabilitiesReport(oidc=OIDCCapabilities(present=True)))
    report = await run(ctx, RunnerConfig(tenant_id="t", enabled=["all"], disabled=[]))
    assert report.checks[0].status == "pass"


async def test_run_fail_when_findings(monkeypatch):
    f = Finding(
        id="x",
        severity="high",
        confidence="high",
        title="t",
        description="d",
        spec_ref="r",
        remediation="m",
    )
    check = _FakeCheck(id="ok", name="ok", findings=[f])
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [check])
    ctx = await _ctx(CapabilitiesReport(oidc=OIDCCapabilities(present=True)))
    report = await run(ctx, RunnerConfig(tenant_id="t", enabled=["all"], disabled=[]))
    assert report.checks[0].status == "fail"
    assert report.severity_counts()["high"] == 1
