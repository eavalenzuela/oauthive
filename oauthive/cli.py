"""Typer CLI.

M1 implements `oauthive discover`. Other commands are visible in the surface
but raise NotImplementedError so users can see where the tool is going.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .capabilities import CapabilitiesReport, derive_from_discovery
from .discovery import DiscoveryError, fetch_discovery
from .legal import LegalGuardError, assert_permitted

app = typer.Typer(
    name="oauthive",
    help="OAuth 2.0 / OIDC / SAML 2.0 misconfiguration tester.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"oauthive {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Root callback — holds global flags."""


@app.command()
def discover(
    url: Annotated[str, typer.Argument(help="URL of .well-known/openid-configuration")],
    tenant_id: Annotated[
        str | None,
        typer.Option("--i-own-this-tenant", help="Tenant identifier you are testing."),
    ] = None,
    allow_public_provider: Annotated[
        bool,
        typer.Option("--allow-public-provider", help="Override the public-provider denylist."),
    ] = False,
    reason: Annotated[
        str | None,
        typer.Option("--reason", help="Required when --allow-public-provider is set."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")] = False,
) -> None:
    """Fetch a discovery doc and print the capabilities probe."""
    # `discover` is read-only against the discovery URL, so we run the legal
    # guard but skip the tenant-id requirement when the operator is just
    # poking at a doc. For any subcommand that actually exercises the IdP
    # (test, cleanup, etc.) the guard requires tenant_id.
    try:
        if allow_public_provider or tenant_id:
            assert_permitted(
                url,
                tenant_id or "discover-only",
                allow_public_provider=allow_public_provider,
                reason=reason,
            )
        else:
            from urllib.parse import urlparse

            from .legal import host_is_public_provider

            host = urlparse(url).hostname or ""
            if host_is_public_provider(host):
                raise LegalGuardError(
                    f"Refusing to fetch from public provider host '{host}'. "
                    "Re-run with --allow-public-provider --reason \"<text>\" "
                    "or --i-own-this-tenant <id> if this is a dedicated tenant."
                )
    except LegalGuardError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    try:
        doc = asyncio.run(fetch_discovery(url))
    except DiscoveryError as e:
        typer.secho(f"discovery failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    caps = CapabilitiesReport(oidc=derive_from_discovery(doc))

    if as_json:
        out = {
            "discovery": doc.model_dump(mode="json"),
            "capabilities": caps.model_dump(mode="json"),
        }
        typer.echo(json.dumps(out, indent=2, default=str))
        return

    typer.secho(f"issuer: {doc.issuer}", bold=True)
    if doc.authorization_endpoint:
        typer.echo(f"  authorization_endpoint:  {doc.authorization_endpoint}")
    if doc.token_endpoint:
        typer.echo(f"  token_endpoint:          {doc.token_endpoint}")
    if doc.userinfo_endpoint:
        typer.echo(f"  userinfo_endpoint:       {doc.userinfo_endpoint}")
    if doc.jwks_uri:
        typer.echo(f"  jwks_uri:                {doc.jwks_uri}")
    if doc.revocation_endpoint:
        typer.echo(f"  revocation_endpoint:     {doc.revocation_endpoint}")
    if doc.end_session_endpoint:
        typer.echo(f"  end_session_endpoint:    {doc.end_session_endpoint}")
    if doc.registration_endpoint:
        typer.echo(f"  registration_endpoint:   {doc.registration_endpoint}")

    typer.secho("\ncapabilities:", bold=True)
    o = caps.oidc
    typer.echo(f"  pkce_supported:            {o.pkce_supported}  methods={o.pkce_methods}")
    typer.echo(f"  dpop_supported:            {o.dpop_supported}")
    typer.echo(f"  mtls_bound_tokens:         {o.mtls_bound_tokens}")
    typer.echo(f"  par_supported:             {o.par_supported}")
    typer.echo(f"  dynamic_registration:      {o.dynamic_registration}")
    typer.echo(f"  revocation_endpoint:       {o.revocation_endpoint}")
    typer.echo(f"  end_session_endpoint:      {o.end_session_endpoint}")
    typer.echo(f"  backchannel_logout:        {o.backchannel_logout}")
    typer.echo(f"  response_types_supported:  {o.supported_response_types}")
    typer.echo(f"  response_modes_supported:  {o.supported_response_modes}")
    typer.echo(f"  grant_types_supported:     {o.supported_grant_types}")
    typer.echo(f"  id_token_signing_algs:     {o.id_token_signing_algs}")


@app.command("saml-discover")
def saml_discover(metadata: Annotated[str, typer.Argument(help="SAML metadata URL or file path")]) -> None:
    """Parse a SAML 2.0 EntityDescriptor and print the capabilities probe."""
    raise NotImplementedError("saml-discover arrives with M10 (SAML metadata parsing).")


@app.command()
def test(
    discovery: Annotated[str | None, typer.Option("--discovery", help="OIDC discovery URL.")] = None,
    saml_metadata: Annotated[
        str | None, typer.Option("--saml-metadata", help="SAML metadata URL or file path.")
    ] = None,
    client_id: Annotated[str | None, typer.Option("--client-id")] = None,
    client_secret: Annotated[str | None, typer.Option("--client-secret")] = None,
    redirect_uri: Annotated[str | None, typer.Option("--redirect-uri")] = None,
    tenant_id: Annotated[str | None, typer.Option("--i-own-this-tenant")] = None,
    allow_public_provider: Annotated[bool, typer.Option("--allow-public-provider")] = False,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
    checks: Annotated[
        str, typer.Option("--checks", help="Comma-separated check ids or 'all'.")
    ] = "all",
    disabled: Annotated[str, typer.Option("--disabled", help="Comma-separated check ids.")] = "",
    per_check_timeout_s: Annotated[float, typer.Option("--timeout")] = 30.0,
    findings_out: Annotated[
        Path, typer.Option("--findings-json", help="Where to write versioned findings JSON.")
    ] = Path("findings.json"),
) -> None:
    """Run the check suite.

    M2 supports OIDC only (redirect_uri check). SAML / remaining OIDC checks /
    HTML report arrive in later milestones.
    """
    import asyncio

    import httpx

    from .capabilities import CapabilitiesReport, derive_from_discovery
    from .client import OAuthClient
    from .context import Context
    from .discovery import DiscoveryError, fetch_discovery
    from .runner import RunnerConfig, make_logger, run

    if saml_metadata:
        typer.secho(
            "--saml-metadata: SAML checks arrive with M10+. Ignoring for now.",
            fg=typer.colors.YELLOW,
        )
    if not discovery:
        typer.secho(
            "error: --discovery is required (SAML-only runs arrive with M10+).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    if not (client_id and redirect_uri):
        typer.secho(
            "error: --client-id and --redirect-uri are required.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        assert_permitted(
            discovery,
            tenant_id,
            allow_public_provider=allow_public_provider,
            reason=reason,
        )
    except LegalGuardError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    async def _go() -> int:
        try:
            doc = await fetch_discovery(discovery)
        except DiscoveryError as e:
            typer.secho(f"discovery failed: {e}", fg=typer.colors.RED, err=True)
            return 1

        caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
        log = make_logger(tenant_id or "")
        async with httpx.AsyncClient(timeout=15.0) as http:
            client = OAuthClient(
                discovery=doc,
                client_id=client_id,
                redirect_uri=redirect_uri,
                client_secret=client_secret,
                http=http,
            )
            ctx = Context(
                tenant_id=tenant_id or "",
                discovery=doc,
                capabilities=caps,
                http=http,
                log=log,
                client=client,
            )
            cfg = RunnerConfig(
                tenant_id=tenant_id or "",
                enabled=[c.strip() for c in checks.split(",") if c.strip()],
                disabled=[c.strip() for c in disabled.split(",") if c.strip()],
                per_check_timeout_s=per_check_timeout_s,
                target_issuer=str(doc.issuer),
                allow_public_provider=allow_public_provider,
                allow_public_reason=reason,
            )
            report = await run(ctx, cfg)

        findings_out.write_text(report.model_dump_json(indent=2))

        from .report import text as text_report

        text_report.render(report)
        typer.echo(f"\nfindings written to {findings_out}")

        counts = report.severity_counts()
        if counts.get("critical", 0) or counts.get("high", 0):
            return 3
        return 0

    raise typer.Exit(code=asyncio.run(_go()))


report_app = typer.Typer(help="Report commands.", no_args_is_help=True)
app.add_typer(report_app, name="report")


@report_app.command("render")
def report_render(findings_json: Path) -> None:
    """Re-render a report from a prior run's findings.json."""
    raise NotImplementedError("report render arrives with M8 (HTML report).")


fixture_app = typer.Typer(help="Self-test fixture (docker-compose).", no_args_is_help=True)
app.add_typer(fixture_app, name="fixture")


@fixture_app.command("up")
def fixture_up() -> None:
    raise NotImplementedError("fixture up arrives with M9 (Keycloak fixture).")


@fixture_app.command("down")
def fixture_down() -> None:
    raise NotImplementedError("fixture down arrives with M9.")


@fixture_app.command("demo")
def fixture_demo() -> None:
    raise NotImplementedError("fixture demo arrives with M9.")


@app.command()
def cleanup(run_id: Annotated[str, typer.Argument()]) -> None:
    """Revoke tokens still on disk from a prior --no-cleanup run."""
    raise NotImplementedError("cleanup arrives alongside the runner (M2+).")


if __name__ == "__main__":
    app()
