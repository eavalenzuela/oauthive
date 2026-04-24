"""Typer CLI.

Commands:
  discover        -- OIDC .well-known probe + capabilities
  saml-discover   -- SAML EntityDescriptor probe + capabilities
  test            -- run the check suite (OIDC and/or SAML)
  cleanup         -- revoke tokens retained by a prior --no-cleanup run
  jose            -- JWT decode / forge (alg_none, hs256_pubkey, kid/jku/x5u)
  saml            -- SAML decode / forge (XSW1-8, comment, XXE, logout request)
  report          -- re-render HTML/Markdown from a prior findings.json
  fixture         -- docker-compose self-test (Keycloak + vuln-sp)
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
def saml_discover(
    metadata: Annotated[str, typer.Argument(help="SAML metadata URL or file path")],
    tenant_id: Annotated[
        str | None,
        typer.Option("--i-own-this-tenant", help="Tenant identifier you are testing."),
    ] = None,
    allow_public_provider: Annotated[bool, typer.Option("--allow-public-provider")] = False,
    reason: Annotated[str | None, typer.Option("--reason")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")] = False,
) -> None:
    """Parse a SAML 2.0 EntityDescriptor and print the capabilities probe."""
    import asyncio
    import json as _json
    from pathlib import Path as _Path

    import httpx

    from .capabilities import CapabilitiesReport, derive_from_saml_metadata
    from .saml.metadata import SAMLMetadataError, parse_metadata

    looks_like_url = metadata.startswith(("http://", "https://"))
    if looks_like_url:
        try:
            if allow_public_provider or tenant_id:
                assert_permitted(
                    metadata,
                    tenant_id or "discover-only",
                    allow_public_provider=allow_public_provider,
                    reason=reason,
                )
            else:
                from urllib.parse import urlparse as _up
                from .legal import host_is_public_provider

                host = _up(metadata).hostname or ""
                if host_is_public_provider(host):
                    raise LegalGuardError(
                        f"refusing to fetch SAML metadata from public provider host {host!r}. "
                        "Re-run with --allow-public-provider --reason \"<text>\" or "
                        "--i-own-this-tenant <id>."
                    )
        except LegalGuardError as e:
            typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    async def _fetch(url: str) -> bytes:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"Accept": "application/samlmetadata+xml, application/xml, */*"})
            r.raise_for_status()
            return r.content

    try:
        if looks_like_url:
            xml = asyncio.run(_fetch(metadata))
        else:
            xml = _Path(metadata).read_bytes()
    except httpx.HTTPError as e:
        typer.secho(f"fetch failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except FileNotFoundError:
        typer.secho(f"metadata file not found: {metadata}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        md = parse_metadata(xml, source_url=metadata if looks_like_url else None)
    except SAMLMetadataError as e:
        typer.secho(f"metadata parse failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    caps = CapabilitiesReport(saml=derive_from_saml_metadata(md))

    if as_json:
        typer.echo(
            _json.dumps(
                {
                    "entity_id": md.entity_id,
                    "role": md.role,
                    "metadata_signed": md.metadata_signed,
                    "sso_services": [
                        {"binding": s.binding, "location": s.location} for s in md.sso_services
                    ],
                    "slo_services": [
                        {"binding": s.binding, "location": s.location} for s in md.slo_services
                    ],
                    "acs_services": [
                        {"binding": s.binding, "location": s.location} for s in md.acs_services
                    ],
                    "name_id_formats": md.name_id_formats,
                    "want_authn_requests_signed": md.want_authn_requests_signed,
                    "want_assertions_signed": md.want_assertions_signed,
                    "capabilities": caps.model_dump(mode="json"),
                },
                indent=2,
            )
        )
        return

    typer.secho(f"entity_id: {md.entity_id}", bold=True)
    typer.echo(f"  role:                        {md.role}")
    typer.echo(f"  metadata_signed:             {md.metadata_signed}")
    typer.echo(f"  want_authn_requests_signed:  {md.want_authn_requests_signed}")
    typer.echo(f"  want_assertions_signed:      {md.want_assertions_signed}")
    typer.echo(f"  sso_bindings:                {md.sso_bindings()}")
    typer.echo(f"  slo_bindings:                {md.slo_bindings()}")
    typer.echo(f"  name_id_formats:             {md.name_id_formats}")
    typer.echo(f"  signing_cert_count:          {len(md.signing_certs())}")
    typer.echo(f"  encryption_cert_count:       {len(md.encryption_certs())}")
    if md.sso_services:
        typer.echo("  sso_services:")
        for s in md.sso_services:
            typer.echo(f"    - {s.binding}  {s.location}")
    if md.acs_services:
        typer.echo("  acs_services:")
        for s in md.acs_services:
            typer.echo(f"    - {s.binding}  {s.location}")


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
    browser: Annotated[
        str,
        typer.Option(
            "--browser",
            help=(
                "How to acquire a live AuthSession for session-dependent checks: "
                "'none' (default, skip session checks), 'manual' (paste callback), "
                "'refresh' (manual once, cache RT), 'playwright' (needs [browser] extra)."
            ),
        ),
    ] = "none",
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
    html_out: Annotated[
        Path | None,
        typer.Option("--out", help="Path to write HTML report (sibling .md also written)."),
    ] = None,
) -> None:
    """Run the check suite against an OIDC and/or SAML target.

    Supply --discovery for OIDC, --saml-metadata for SAML, or both. For OIDC
    runs --client-id and --redirect-uri are required. Writes findings.json
    and, when --out is given, HTML + sibling Markdown. Exits non-zero when
    any critical or high finding lands.
    """
    import asyncio

    import httpx

    from .capabilities import CapabilitiesReport, derive_from_discovery
    from .client import OAuthClient
    from .context import Context
    from .discovery import DiscoveryError, fetch_discovery
    from .runner import RunnerConfig, make_logger, run

    if not discovery and not saml_metadata:
        typer.secho(
            "error: provide --discovery and/or --saml-metadata.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    if discovery and not (client_id and redirect_uri):
        typer.secho(
            "error: --client-id and --redirect-uri are required when --discovery is set.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        gate_url = discovery or saml_metadata
        assert_permitted(
            gate_url,
            tenant_id,
            allow_public_provider=allow_public_provider,
            reason=reason,
        )
    except LegalGuardError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    async def _go() -> int:
        doc = None
        saml_md = None
        if discovery:
            try:
                doc = await fetch_discovery(discovery)
            except DiscoveryError as e:
                typer.secho(f"discovery failed: {e}", fg=typer.colors.RED, err=True)
                return 1

        if saml_metadata:
            from .capabilities import derive_from_saml_metadata
            from .saml.metadata import SAMLMetadataError, parse_metadata

            try:
                fetched_url: str | None = None
                if saml_metadata.startswith(("http://", "https://")):
                    fetched_url = saml_metadata
                    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
                        r = await c.get(
                            saml_metadata,
                            headers={
                                "Accept": "application/samlmetadata+xml, application/xml, */*"
                            },
                        )
                        r.raise_for_status()
                        xml = r.content
                else:
                    xml = Path(saml_metadata).read_bytes()
                saml_md = parse_metadata(xml, source_url=fetched_url)
            except (httpx.HTTPError, FileNotFoundError, SAMLMetadataError) as e:
                typer.secho(f"saml metadata failed: {e}", fg=typer.colors.RED, err=True)
                return 1

        caps = CapabilitiesReport()
        if doc is not None:
            caps.oidc = derive_from_discovery(doc)
        if saml_md is not None:
            from .capabilities import derive_from_saml_metadata

            caps.saml = derive_from_saml_metadata(saml_md)

        log = make_logger(tenant_id or "")
        async with httpx.AsyncClient(timeout=15.0) as http:
            client = None
            if doc is not None and client_id and redirect_uri:
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
                saml_metadata=saml_md,
            )
            driver = None
            if browser != "none":
                from .browser import BrowserError, build_driver
                from .browser.refresh import RefreshDriver

                try:
                    if browser == "refresh":
                        driver = RefreshDriver(tenant_id=tenant_id or "")
                    else:
                        driver = build_driver(browser)
                except BrowserError as e:
                    typer.secho(f"browser init failed: {e}", fg=typer.colors.RED, err=True)
                    return 2

            cfg = RunnerConfig(
                tenant_id=tenant_id or "",
                enabled=[c.strip() for c in checks.split(",") if c.strip()],
                disabled=[c.strip() for c in disabled.split(",") if c.strip()],
                per_check_timeout_s=per_check_timeout_s,
                target_issuer=(str(doc.issuer) if doc is not None else (
                    saml_md.entity_id if saml_md is not None else None
                )),
                allow_public_provider=allow_public_provider,
                allow_public_reason=reason,
                session_mode=session_mode,
                cleanup_tokens=not no_cleanup,
                driver=driver,
            )
            report = await run(ctx, cfg)

            # Token cleanup: revoke any session still attached to the context.
            cleanup_block: dict | None = None
            from .cleanup import revoke_session as _revoke

            session = getattr(ctx, "session", None)
            if session and not no_cleanup and client is not None:
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

        from .report import html as html_report
        from .report import markdown as md_report
        from .report import text as text_report

        text_report.render(report)
        typer.echo(f"\nfindings written to {findings_out}")
        if html_out is not None:
            html_out.write_text(
                html_report.render(report, no_cleanup_banner=no_cleanup)
            )
            md_path = html_out.with_suffix(".md")
            md_path.write_text(
                md_report.render(report, no_cleanup_banner=no_cleanup)
            )
            typer.echo(f"html report: {html_out}")
            typer.echo(f"markdown:    {md_path}")

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


saml_app = typer.Typer(help="SAML tooling (decode + forge).", no_args_is_help=True)
app.add_typer(saml_app, name="saml")


@saml_app.command("decode")
def saml_decode(
    source: Annotated[
        str,
        typer.Argument(
            help=(
                "Path to an XML file, '-' for stdin, or a base64-encoded "
                "SAMLRequest/SAMLResponse value from a POST binding."
            )
        ),
    ],
    redirect_b64: Annotated[
        bool,
        typer.Option(
            "--redirect-b64",
            help="Treat source as the base64(DEFLATE(xml)) query value from the HTTP-Redirect binding.",
        ),
    ] = False,
) -> None:
    """Pretty-print a SAML AuthnRequest or Response."""
    import base64 as _b64
    import sys

    from lxml import etree

    from .saml.bindings import decode_deflate_b64

    if source == "-":
        raw = sys.stdin.buffer.read()
    elif source.startswith("<?xml") or source.startswith("<"):
        raw = source.encode()
    else:
        p = Path(source)
        if p.exists():
            raw = p.read_bytes()
        else:
            # Treat as base64 from a POST binding
            try:
                raw = _b64.b64decode(source)
            except Exception:
                typer.secho("error: could not decode source", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)

    if redirect_b64:
        raw = decode_deflate_b64(raw.decode() if isinstance(raw, bytes) else raw)

    try:
        root = etree.fromstring(raw)
    except etree.XMLSyntaxError as e:
        typer.secho(f"XML syntax error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    pretty = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="utf-8")
    typer.echo(pretty.decode())


@saml_app.command("forge")
def saml_forge(
    attack: Annotated[
        str,
        typer.Option(
            "--attack",
            help=(
                "strip_signature | downgrade_sig_alg | swap_key_info | "
                "inject_nameid_comment | inject_nameid_attribute | "
                "xsw1..xsw8 | xxe_external_entity | xxe_parameter_entity | "
                "xxe_bounded_expansion | build_logout_request"
            ),
        ),
    ],
    source: Annotated[
        Path | None,
        typer.Option(
            "--from-file",
            help="Path to an XML Response (required for strip/downgrade/swap/xsw/comment).",
        ),
    ] = None,
    attacker_cert_b64: Annotated[
        str | None,
        typer.Option("--attacker-cert-b64", help="Base64 cert for swap_key_info."),
    ] = None,
    victim: Annotated[
        str | None,
        typer.Option("--victim", help="Victim NameID for inject_nameid_{comment,attribute}."),
    ] = None,
    suffix: Annotated[
        str, typer.Option("--suffix", help="Suffix after the injected comment.")
    ] = ".attacker.test",
    evil_name_id: Annotated[
        str | None,
        typer.Option("--evil-name-id", help="NameID to substitute in the evil assertion for xsw*."),
    ] = None,
    oob_url: Annotated[
        str | None,
        typer.Option("--oob-url", help="Out-of-band URL for XXE probes."),
    ] = None,
    issuer: Annotated[
        str | None, typer.Option("--issuer", help="SP entity id for XXE AuthnRequest.")
    ] = None,
    acs_url: Annotated[
        str | None, typer.Option("--acs-url", help="ACS URL for XXE AuthnRequest.")
    ] = None,
    destination: Annotated[
        str | None,
        typer.Option("--destination", help="IdP SSO endpoint (Destination) for XXE AuthnRequest."),
    ] = None,
    expansion_depth: Annotated[
        int,
        typer.Option(
            "--expansion-depth",
            help="Depth for xxe_bounded_expansion (clamped to 2..5 to avoid genuine DoS).",
        ),
    ] = 4,
    name_id: Annotated[
        str | None,
        typer.Option("--name-id", help="Target NameID for build_logout_request."),
    ] = None,
    session_index: Annotated[
        str | None,
        typer.Option("--session-index", help="Optional SessionIndex for build_logout_request."),
    ] = None,
) -> None:
    """Forge a malicious SAML Response variant or an XXE-flavoured AuthnRequest."""
    from .saml.forge import (
        SAMLForgeError,
        XSW_VARIANTS,
        build_logout_request,
        downgrade_sig_alg,
        inject_nameid_attribute_comment,
        inject_nameid_comment,
        strip_signature,
        swap_key_info,
        xxe_bounded_expansion,
        xxe_external_entity,
        xxe_parameter_entity,
    )

    def _require_xml() -> bytes:
        if source is None:
            typer.secho("error: --from-file is required", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        return source.read_bytes()

    def _require_xxe_params() -> tuple[str, str, str]:
        missing = [
            n
            for n, v in (("--issuer", issuer), ("--acs-url", acs_url), ("--destination", destination))
            if not v
        ]
        if missing:
            typer.secho(
                f"error: XXE attacks require {', '.join(missing)}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        return issuer, acs_url, destination  # type: ignore[return-value]

    try:
        if attack == "strip_signature":
            out = strip_signature(_require_xml())
        elif attack == "downgrade_sig_alg":
            out = downgrade_sig_alg(_require_xml())
        elif attack == "swap_key_info":
            if not attacker_cert_b64:
                typer.secho("--attacker-cert-b64 is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            out = swap_key_info(_require_xml(), attacker_cert_b64)
        elif attack == "inject_nameid_comment":
            if not victim:
                typer.secho("--victim is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            out = inject_nameid_comment(_require_xml(), victim, suffix=suffix)
        elif attack == "inject_nameid_attribute":
            if not victim:
                typer.secho("--victim is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            out = inject_nameid_attribute_comment(_require_xml(), victim)
        elif attack in XSW_VARIANTS:
            if not evil_name_id:
                typer.secho("--evil-name-id is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            out = XSW_VARIANTS[attack](_require_xml(), evil_name_id)
        elif attack == "xxe_external_entity":
            if not oob_url:
                typer.secho("--oob-url is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            iss, acs, dest = _require_xxe_params()
            out = xxe_external_entity(oob_url=oob_url, issuer=iss, acs_url=acs, destination=dest)
        elif attack == "xxe_parameter_entity":
            if not oob_url:
                typer.secho("--oob-url is required", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)
            iss, acs, dest = _require_xxe_params()
            out = xxe_parameter_entity(oob_url=oob_url, issuer=iss, acs_url=acs, destination=dest)
        elif attack == "xxe_bounded_expansion":
            iss, acs, dest = _require_xxe_params()
            out = xxe_bounded_expansion(
                issuer=iss, acs_url=acs, destination=dest, depth=expansion_depth
            )
        elif attack == "build_logout_request":
            missing = [
                n
                for n, v in (
                    ("--issuer", issuer),
                    ("--destination", destination),
                    ("--name-id", name_id),
                )
                if not v
            ]
            if missing:
                typer.secho(
                    f"error: build_logout_request requires {', '.join(missing)}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=2)
            out = build_logout_request(
                issuer=issuer,  # type: ignore[arg-type]
                destination=destination,  # type: ignore[arg-type]
                name_id=name_id,  # type: ignore[arg-type]
                session_index=session_index,
            )
        else:
            typer.secho(f"unknown attack {attack!r}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
    except SAMLForgeError as e:
        typer.secho(f"forge failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(out.decode())


report_app = typer.Typer(help="Report commands.", no_args_is_help=True)
app.add_typer(report_app, name="report")


@report_app.command("render")
def report_render(
    findings_json: Annotated[Path, typer.Argument(exists=True, help="Path to findings.json")],
    out: Annotated[
        Path | None, typer.Option("--out", help="HTML output path (also writes sibling .md).")
    ] = None,
    format: Annotated[
        str, typer.Option("--format", help="One of: html, md. Ignored if --out is set.")
    ] = "html",
) -> None:
    """Re-render a report from a prior run's findings.json.

    Without --out, writes to stdout in the requested --format.
    """
    import json as _json

    from .report import html as html_report
    from .report import markdown as md_report
    from .report.schema import Report, SCHEMA_VERSION

    data = _json.loads(findings_json.read_text())
    if data.get("schema_version") != SCHEMA_VERSION:
        typer.secho(
            f"warning: findings.json schema_version {data.get('schema_version')} "
            f"!= {SCHEMA_VERSION}; rendering may miss newer fields.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    # Drop cleanup_report block so the Report validator doesn't reject it.
    data.pop("cleanup_report", None)
    report = Report.model_validate(data)

    if out is not None:
        out.write_text(html_report.render(report))
        md_path = out.with_suffix(".md")
        md_path.write_text(md_report.render(report))
        typer.echo(f"html report: {out}")
        typer.echo(f"markdown:    {md_path}")
        return

    if format == "html":
        typer.echo(html_report.render(report))
    elif format == "md":
        typer.echo(md_report.render(report))
    else:
        typer.secho(f"unknown --format {format!r}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)


fixture_app = typer.Typer(help="Self-test fixture (docker-compose).", no_args_is_help=True)
app.add_typer(fixture_app, name="fixture")


@fixture_app.command("up")
def fixture_up() -> None:
    """docker compose up the Keycloak self-test fixture."""
    from .fixture import FixtureError, run, up_cmd

    try:
        cmd = up_cmd()
    except FixtureError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    typer.echo(f"running: {' '.join(cmd.argv)} (cwd={cmd.cwd})")
    rc = run(cmd)
    if rc != 0:
        raise typer.Exit(code=rc)
    typer.secho(
        "keycloak starting. Discovery URL:\n  " +
        "http://127.0.0.1:8080/realms/oauthive-dev/.well-known/openid-configuration",
        fg=typer.colors.GREEN,
    )


@fixture_app.command("down")
def fixture_down(
    volumes: Annotated[
        bool,
        typer.Option("--volumes/--keep-volumes", help="Remove the docker volumes too."),
    ] = True,
) -> None:
    """docker compose down the fixture."""
    from .fixture import FixtureError, down_cmd, run

    try:
        cmd = down_cmd(volumes=volumes)
    except FixtureError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    typer.echo(f"running: {' '.join(cmd.argv)} (cwd={cmd.cwd})")
    rc = run(cmd)
    raise typer.Exit(code=rc)


@fixture_app.command("demo")
def fixture_demo(
    wait_s: Annotated[float, typer.Option("--wait", help="Seconds to wait for readiness.")] = 90.0,
    client_id: Annotated[
        str, typer.Option("--client-id")
    ] = "oauthive-public-no-pkce",
    redirect_uri: Annotated[
        str, typer.Option("--redirect-uri")
    ] = "https://app.example.test/cb",
    saml: Annotated[
        bool,
        typer.Option(
            "--saml/--no-saml",
            help="Also run the SAML check suite against Keycloak's SAML IdP.",
        ),
    ] = True,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--no-strict",
            help=(
                "Assert that EXPECTED_FINDING_IDS are all present; exit non-zero otherwise. "
                "Use in CI to catch regressions in the check suite."
            ),
        ),
    ] = True,
) -> None:
    """Run the check suite against the running fixture and assert expected ids."""
    import asyncio

    import httpx

    from .capabilities import (
        CapabilitiesReport,
        derive_from_discovery,
        derive_from_saml_metadata,
    )
    from .client import OAuthClient
    from .context import Context
    from .discovery import DiscoveryError, fetch_discovery
    from .fixture import (
        DISCOVERY_URL,
        EXPECTED_FINDING_IDS,
        EXPECTED_SAML_FINDING_IDS,
        FixtureError,
        SAML_METADATA_URL,
        wait_for_ready,
    )
    from .runner import RunnerConfig, make_logger, run as run_checks
    from .saml.metadata import SAMLMetadataError, parse_metadata

    async def _go() -> int:
        try:
            await wait_for_ready(timeout_s=wait_s)
        except FixtureError as e:
            typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
            return 1
        try:
            doc = await fetch_discovery(DISCOVERY_URL)
        except DiscoveryError as e:
            typer.secho(f"discovery failed: {e}", fg=typer.colors.RED, err=True)
            return 1

        saml_md = None
        if saml:
            async with httpx.AsyncClient(timeout=15.0) as c:
                try:
                    r = await c.get(
                        SAML_METADATA_URL,
                        headers={"Accept": "application/samlmetadata+xml, application/xml, */*"},
                    )
                    r.raise_for_status()
                    saml_md = parse_metadata(r.content, source_url=SAML_METADATA_URL)
                except (httpx.HTTPError, SAMLMetadataError) as e:
                    typer.secho(
                        f"saml metadata fetch failed: {e}", fg=typer.colors.YELLOW
                    )
                    saml_md = None

        caps = CapabilitiesReport(oidc=derive_from_discovery(doc))
        if saml_md is not None:
            caps.saml = derive_from_saml_metadata(saml_md)

        async with httpx.AsyncClient(timeout=15.0) as http:
            client = OAuthClient(
                discovery=doc,
                client_id=client_id,
                redirect_uri=redirect_uri,
                http=http,
            )
            ctx = Context(
                tenant_id="oauthive-fixture",
                discovery=doc,
                capabilities=caps,
                http=http,
                log=make_logger("oauthive-fixture"),
                client=client,
                saml_metadata=saml_md,
            )
            cfg = RunnerConfig(
                tenant_id="oauthive-fixture",
                enabled=["all"],
                disabled=[],
                target_issuer=str(doc.issuer),
            )
            report = await run_checks(ctx, cfg)

        from .report import text as text_report

        text_report.render(report)

        if strict:
            got = {f.id for c in report.checks for f in c.findings}
            expected = set(EXPECTED_FINDING_IDS)
            if saml_md is not None:
                expected |= EXPECTED_SAML_FINDING_IDS
            missing = expected - got
            if missing:
                typer.secho(
                    f"\nfixture demo: expected findings missing: {sorted(missing)}",
                    fg=typer.colors.RED,
                    err=True,
                )
                return 2
            typer.secho("\nfixture demo: all expected findings present", fg=typer.colors.GREEN)
        return 0

    raise typer.Exit(code=asyncio.run(_go()))


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
