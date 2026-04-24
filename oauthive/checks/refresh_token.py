"""Refresh token lifecycle.

Passive (no session needed):
  - refresh_token.grant_not_supported : discovery does not advertise
    refresh_token in grant_types_supported. Informational -- may be
    intentional for very short-lived access clients.

Session-dependent:
  - refresh_token.rotation_not_enforced : OAuth 2.0 Security BCP sec 4.12
    strongly recommends rotation for public clients. Use the RT once, then
    attempt to reuse the original; if the IdP accepts the reuse, rotation
    is not enforced.

  - refresh_token.binding_to_client_weak : a second client is configured
    via [client.secondary]. The primary client's RT is presented at /token
    with the secondary client's credentials; a sane IdP rejects this.
    This lands only when ctx.client has a `secondary` attribute (populated
    by the caller from config).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..client import TokenError
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class RefreshTokenCheck:
    id = "refresh_token"
    name = "refresh token lifecycle"
    parallel_safe = False  # mutates the shared session (consumes RT)
    requires_fresh_auth = True
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        findings: list[Finding] = []

        advertised_grants = set(ctx.capabilities.oidc.supported_grant_types)
        if "refresh_token" not in advertised_grants:
            findings.append(
                Finding(
                    id="refresh_token.grant_not_supported",
                    severity="info",
                    confidence="high",
                    title="Discovery does not advertise the refresh_token grant",
                    description=(
                        "grant_types_supported does not include 'refresh_token'. "
                        "This may be intentional (very short-lived access tokens) "
                        "or a misconfiguration that forces clients to re-prompt."
                    ),
                    spec_ref="RFC 6749 sec 6; OIDC Discovery sec 3",
                    remediation=(
                        "Enable the refresh_token grant with rotation if clients "
                        "need long-lived access without re-prompting users."
                    ),
                    evidence={"advertised_grants": sorted(advertised_grants)},
                )
            )
            return findings

        session = await ctx.ensure_session(scope="openid offline_access") if ctx.session_factory else None
        if session is None or not session.refresh_token:
            return findings  # session-dependent sub-probes need an RT

        original_rt = session.refresh_token
        client = ctx.client

        # Use the RT once. Success => we have new tokens. Failure here is not
        # the finding we're hunting for; it just means we can't test rotation.
        try:
            refreshed = await client.refresh(original_rt, tenant_id=ctx.tenant_id)
        except TokenError as e:
            ctx.log.warning("refresh_token.first_use_failed", error=str(e))
            return findings

        # Try to reuse the *original* RT. If this succeeds, rotation is not
        # enforced (or the RT is a JWT-style statelessly-verifiable token that
        # the IdP doesn't single-use track).
        try:
            replay = await client.refresh(original_rt, tenant_id=ctx.tenant_id)
        except TokenError:
            replay = None

        if replay is not None:
            findings.append(
                Finding(
                    id="refresh_token.rotation_not_enforced",
                    severity="high",
                    confidence="high",
                    title="Refresh token accepted after prior use (rotation not enforced)",
                    description=(
                        "After exchanging a refresh token for a new access token, "
                        "re-presenting the same refresh token was accepted. OAuth "
                        "2.0 Security BCP sec 4.12 and OAuth 2.1 sec 4.14 require "
                        "rotation-with-reuse-detection for public clients; without "
                        "it, a stolen RT remains valid indefinitely."
                    ),
                    spec_ref="OAuth 2.0 Security BCP sec 4.12; OAuth 2.1 sec 4.14",
                    remediation=(
                        "Enable refresh-token rotation. On reuse of an already-"
                        "exchanged RT, revoke the entire token family and force "
                        "re-authentication."
                    ),
                    evidence={
                        "first_exchange_ok": True,
                        "replay_ok": True,
                    },
                )
            )

        # Update the cached session to the newest refreshed one so downstream
        # checks see a live AT.
        ctx.session = refreshed

        # Cross-client binding: does the IdP accept the primary's RT at the
        # secondary client's credentials?
        secondary = getattr(ctx, "secondary_client", None)
        if secondary is not None and refreshed.refresh_token:
            try:
                _ = await secondary.refresh(refreshed.refresh_token, tenant_id=ctx.tenant_id)
                cross_ok = True
            except TokenError:
                cross_ok = False
            if cross_ok:
                findings.append(
                    Finding(
                        id="refresh_token.binding_to_client_weak",
                        severity="critical",
                        confidence="high",
                        title="Refresh token accepted at a different client",
                        description=(
                            "A refresh token minted for client A was accepted "
                            "when presented to the token endpoint with client B's "
                            "credentials. An attacker who compromises any client "
                            "can trade an intercepted RT for tokens in their own "
                            "name."
                        ),
                        spec_ref="RFC 6749 sec 6; OAuth 2.0 Security BCP sec 4.12",
                        remediation=(
                            "Bind refresh tokens to the issuing client and reject "
                            "presentations with a different client_id."
                        ),
                        evidence={
                            "primary_client_id": client.client_id,
                            "secondary_client_id": secondary.client_id,
                        },
                    )
                )

        return findings
