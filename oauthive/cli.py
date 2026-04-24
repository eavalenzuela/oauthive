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
    session_mode: Annotated[str, typer.Option("--session-mode")] = "isolated",
    no_cleanup: Annotated[
        bool,
        typer.Option(
            "--no-cleanup",
            help="Retain tokens on disk after the run (for debugging).",
        ),
    ] = False,
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
                session_mode=session_mode,
                cleanup_tokens=not no_cleanup,
            )
            report = await run(ctx, cfg)

            # Token cleanup: revoke any session still attached to the context.
            cleanup_block: dict | None = None
            from .cleanup import revoke_session as _revoke

            session = getattr(ctx, "session", None)
            if session and not no_cleanup:
                cr = await _revoke(client, session)
                cleanup_block = cr.to_dict()
            elif session and no_cleanup:
                typer.secho(
                    "LIVE TOKENS RETAINED -- run 'oauthive cleanup <tenant-id>' when done.",
                    fg=typer.colors.BRIGHT_YELLOW,
                    bold=True,
                )

        payload = report.model_dump(mode="json")
        if cleanup_block is not None:
            payload["cleanup_report"] = cleanup_block
        findings_out.write_text(json.dumps(payload, indent=2, default=str))

        from .report import text as text_report

        text_report.render(report)
        typer.echo(f"\nfindings written to {findings_out}")

        counts = report.severity_counts()
        if counts.get("critical", 0) or counts.get("high", 0):
            return 3
        return 0

    raise typer.Exit(code=asyncio.run(_go()))


jose_app = typer.Typer(help="JOSE / JWT tooling (for use against your own RP).", no_args_is_help=True)
app.add_typer(jose_app, name="jose")


@jose_app.command("decode")
def jose_decode(
    token: Annotated[str, typer.Argument(help="Compact JWS token (3 b64url parts).")],
) -> None:
    """Print header and claims of a JWT without verifying."""
    import json as _json

    from .jose.verify import unsafe_decode

    d = unsafe_decode(token)
    typer.secho("header:", bold=True)
    typer.echo(_json.dumps(d.header, indent=2))
    typer.secho("claims:", bold=True)
    typer.echo(_json.dumps(d.claims, indent=2))


@jose_app.command("forge")
def jose_forge(
    attack: Annotated[
        str,
        typer.Option(
            "--attack",
            help="One of: alg_none, hs256_pubkey, kid_inject, jku_pivot, x5u_pivot.",
        ),
    ],
    claims_json: Annotated[
        Path | None,
        typer.Option("--claims", help="Path to a JSON file with the token claims."),
    ] = None,
    from_token: Annotated[
        str | None,
        typer.Option("--from-token", help="Extract claims from this existing token."),
    ] = None,
    public_key_pem: Annotated[
        Path | None,
        typer.Option("--public-key-pem", help="Provider's public key PEM (hs256_pubkey)."),
    ] = None,
    kid: Annotated[str | None, typer.Option("--kid", help="Value for the kid header.")] = None,
    jku: Annotated[str | None, typer.Option("--jku", help="Value for the jku header.")] = None,
    x5u: Annotated[str | None, typer.Option("--x5u", help="Value for the x5u header.")] = None,
    attacker_jwks_out: Annotated[
        Path | None,
        typer.Option(
            "--attacker-jwks-out",
            help="Where to write the attacker-controlled JWKS for jku/x5u pivots.",
        ),
    ] = None,
) -> None:
    """Forge a malicious JWS. Output goes to stdout.

    Intended for operators to pipe into curl against their own RP/SP for
    impact validation. Every attack is something the operator should have
    explicit authorization for.
    """
    import json as _json

    from .jose.forge import (
        RSASigner,
        forge_alg_none,
        forge_hs256_with_pubkey,
        forge_with_header,
        generate_attacker_rsa,
    )
    from .jose.verify import unsafe_decode

    if claims_json is None and from_token is None:
        typer.secho(
            "error: provide --claims <file> or --from-token <token>",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    if claims_json is not None:
        claims = _json.loads(claims_json.read_text())
    else:
        claims = unsafe_decode(from_token).claims  # type: ignore[arg-type]

    if attack == "alg_none":
        typer.echo(forge_alg_none(claims))
        return

    if attack == "hs256_pubkey":
        if public_key_pem is None:
            typer.secho(
                "error: --public-key-pem is required for hs256_pubkey",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        pem_bytes = public_key_pem.read_bytes()
        typer.echo(forge_hs256_with_pubkey(claims, pem_bytes, kid=kid))
        return

    if attack in ("kid_inject", "jku_pivot", "x5u_pivot"):
        priv, _pub, jwk = generate_attacker_rsa()
        header: dict = {"alg": "RS256", "typ": "JWT"}
        if attack == "kid_inject":
            if kid is None:
                typer.secho("error: --kid is required for kid_inject", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            header["kid"] = kid
        elif attack == "jku_pivot":
            if jku is None:
                typer.secho("error: --jku is required for jku_pivot", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            header["jku"] = jku
            header["kid"] = jwk["kid"]
        else:  # x5u_pivot
            if x5u is None:
                typer.secho("error: --x5u is required for x5u_pivot", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            header["x5u"] = x5u
            header["kid"] = jwk["kid"]
        typer.echo(forge_with_header(claims, header, RSASigner(priv)))
        if attacker_jwks_out is not None:
            attacker_jwks_out.write_text(_json.dumps({"keys": [jwk]}, indent=2))
            typer.secho(
                f"attacker JWKS written to {attacker_jwks_out} (serve at {jku or x5u})",
                fg=typer.colors.YELLOW,
                err=True,
            )
        return

    typer.secho(f"error: unknown --attack {attack!r}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2)


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
def cleanup(
    tenant_id: Annotated[str, typer.Argument(help="Tenant id whose session should be revoked.")],
    discovery: Annotated[str, typer.Option("--discovery", help="OIDC discovery URL.")],
    client_id: Annotated[str, typer.Option("--client-id")],
    client_secret: Annotated[str | None, typer.Option("--client-secret")] = None,
    redirect_uri: Annotated[
        str, typer.Option("--redirect-uri", help="Registered redirect_uri (required by some IdPs).")
    ] = "http://127.0.0.1/cb",
    allow_public_provider: Annotated[bool, typer.Option("--allow-public-provider")] = False,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
) -> None:
    """Revoke tokens still on disk from a prior --no-cleanup run."""
    import asyncio

    import httpx

    from .cleanup import revoke_session
    from .client import OAuthClient
    from .discovery import DiscoveryError, fetch_discovery
    from .session import AuthSession

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

    session = AuthSession.load(tenant_id)
    if session is None:
        typer.secho(
            f"no session on disk for tenant_id={tenant_id!r}; nothing to do.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=0)

    async def _go() -> None:
        try:
            doc = await fetch_discovery(discovery)
        except DiscoveryError as e:
            typer.secho(f"discovery failed: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        async with httpx.AsyncClient(timeout=15.0) as http:
            client = OAuthClient(
                discovery=doc,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                http=http,
            )
            report = await revoke_session(client, session)
        for o in report.outcomes:
            colour = typer.colors.GREEN if o.revoked else typer.colors.RED
            typer.secho(
                f"  {o.token_kind:15} revoked={o.revoked}  {o.detail or ''}", fg=colour
            )

    asyncio.run(_go())


if __name__ == "__main__":
    app()
