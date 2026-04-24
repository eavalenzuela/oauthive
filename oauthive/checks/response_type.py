"""response_type posture.

OAuth 2.0 Security BCP sec 2.1.2 and OAuth 2.1 draft: implicit flows
(response_type=token, token id_token) deliver tokens through the user-agent
fragment, exposing them to browser history, referer leaks, and XSS that
doesn't need to reach the token endpoint. OAuth 2.1 removes the implicit
flow entirely.

This check:
  - Flags that the IdP advertises implicit response_types at all.
  - Flags when implicit actually works at /authorize (issues a token when
    response_type=token is requested).
  - Flags response_mode=fragment being used for flows that deliver sensitive
    artifacts, where form_post would be safer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context

IMPLICIT_RTS = {"token", "token id_token", "id_token token"}


class ResponseTypeCheck:
    id = "response_type"
    name = "response_type / response_mode posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            return []
        findings: list[Finding] = []

        advertised = set(ctx.capabilities.oidc.supported_response_types)
        advertised_implicit = advertised & IMPLICIT_RTS
        if advertised_implicit:
            findings.append(
                Finding(
                    id="response_type.implicit_advertised",
                    severity="low",
                    confidence="high",
                    title="Implicit flow response_types are advertised",
                    description=(
                        "Discovery advertises response_types that deliver tokens "
                        "through the fragment: "
                        f"{sorted(advertised_implicit)}. OAuth 2.0 Security BCP "
                        "sec 2.1.2 and OAuth 2.1 remove these flows in favor of "
                        "the code flow with PKCE."
                    ),
                    spec_ref="OAuth 2.0 Security BCP sec 2.1.2; OAuth 2.1 draft sec 4.1.1.3",
                    remediation=(
                        "Remove implicit response_types from discovery and disable "
                        "them in client configuration. Migrate any client using "
                        "them to authorization_code + PKCE."
                    ),
                    evidence={"implicit_types": sorted(advertised_implicit)},
                )
            )

        # Probe response_type=token if advertised.
        if "token" in advertised:
            resp = await client.probe_authorization(response_type="token", scope="openid")
            if resp.accepted_redirect and resp.location:
                parsed = urlparse(resp.location)
                merged = {**parse_qs(parsed.query), **parse_qs(parsed.fragment)}
                if "access_token" in merged:
                    findings.append(
                        Finding(
                            id="response_type.implicit_token_issued",
                            severity="high",
                            confidence="high",
                            title="Implicit flow returned an access_token",
                            description=(
                                "Requesting response_type=token resulted in an "
                                "access_token delivered in the URL fragment. "
                                "Fragment-delivered tokens leak to browser history "
                                "and referer; OAuth 2.1 removes this flow."
                            ),
                            spec_ref="OAuth 2.0 Security BCP sec 2.1.2",
                            poc_url=resp.location,
                            remediation=(
                                "Disable implicit response_types on this client "
                                "and migrate to the code flow with PKCE."
                            ),
                            evidence={"callback_keys": sorted(merged.keys())},
                        )
                    )

        # response_mode=fragment for the code flow is a weaker choice than
        # form_post when the redirect target is an HTTPS web app; flag if the
        # IdP advertises both and accepts ?response_mode=fragment with code flow.
        modes = set(ctx.capabilities.oidc.supported_response_modes)
        if {"fragment", "form_post"} <= modes:
            resp = await client.probe_authorization(
                extra={"response_mode": "fragment"},
            )
            if resp.accepted_redirect:
                findings.append(
                    Finding(
                        id="response_type.fragment_mode_accepted_for_code",
                        severity="info",
                        confidence="medium",
                        title="response_mode=fragment accepted for the code flow",
                        description=(
                            "form_post keeps the code out of browser history and "
                            "referer headers. fragment is appropriate for native / "
                            "SPA callbacks but weaker for server-side RPs."
                        ),
                        spec_ref="OAuth 2.0 Multiple Response Type Encoding Practices sec 2",
                        poc_url=resp.location,
                        remediation=(
                            "Web-server RPs should request response_mode=form_post "
                            "(or query) rather than fragment."
                        ),
                        evidence={"advertised_modes": sorted(modes)},
                    )
                )

        return findings
