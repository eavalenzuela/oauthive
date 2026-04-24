"""Single Logout posture.

Metadata-level:
  - saml_slo.no_single_logout_service : IdP does not advertise any
    SingleLogoutService endpoint; RPs cannot initiate SLO.
  - saml_slo.single_logout_requires_signature_check : advertises SLO but
    metadata can't tell us whether LogoutRequests are accepted unsigned.

Exercise pointer:
  - Build an unsigned samlp:LogoutRequest via
    `oauthive saml forge --attack build_logout_request` and send to the
    advertised SLO endpoint; an IdP that accepts this from a non-session
    requester is broken (anyone can terminate anyone's session).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLSLOCheck:
    id = "saml_slo"
    name = "SAML Single Logout posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []
        findings: list[Finding] = []

        if not md.slo_services:
            findings.append(
                Finding(
                    id="saml_slo.no_single_logout_service",
                    severity="medium",
                    confidence="high",
                    title="No SingleLogoutService advertised",
                    description=(
                        "Without an SLO endpoint, RPs cannot centrally "
                        "terminate the user's IdP session when they log out "
                        "of the RP. Federated single sign-out is effectively "
                        "impossible."
                    ),
                    spec_ref="SAML 2.0 Profiles sec 4.4; SAML Metadata sec 2.4.1",
                    remediation=(
                        "Enable SLO and advertise SingleLogoutService with at "
                        "least one binding (HTTP-POST or HTTP-Redirect)."
                    ),
                    evidence={"entity_id": md.entity_id},
                )
            )
            return findings

        endpoints = [
            f"{s.location} ({s.binding.rsplit(':', 1)[-1]})" for s in md.slo_services
        ]
        findings.append(
            Finding(
                id="saml_slo.exercise_unsigned_logout",
                severity="info",
                confidence="high",
                title="Exercise unsigned LogoutRequest acceptance against your IdP",
                description=(
                    "Build an unsigned samlp:LogoutRequest and POST (or "
                    "redirect-encode) it to an advertised SLO endpoint.\n\n"
                    "  oauthive saml forge --attack build_logout_request "
                    "--issuer <your sp> --destination <sso-slo-endpoint> "
                    "--name-id <target user nameid>\n\n"
                    "A sane IdP rejects this (either because signing is "
                    "required or because the request doesn't originate from a "
                    "live session). An IdP that logs the target user out "
                    "anyway is broken -- anyone who can guess a NameID can "
                    "CSRF logouts across the federation."
                ),
                spec_ref=(
                    "SAML 2.0 Profiles sec 4.4.3.1; SAML 2.0 Security and "
                    "Privacy Considerations sec 6.1.5"
                ),
                remediation=(
                    "Require signed LogoutRequests (WantAuthnRequestsSigned "
                    "applies to all requests from the SP, and most IdPs "
                    "extend it to LogoutRequest). Additionally bind SLO to a "
                    "live session cookie so unsolicited requests are dropped."
                ),
                evidence={"slo_endpoints": endpoints, "entity_id": md.entity_id},
            )
        )
        return findings
