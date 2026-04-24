"""DPoP (RFC 9449) and mTLS-binding posture.

Metadata-level observations:

  dpop.advertised_with_mtls_binding
    Both DPoP (dpop_signing_alg_values_supported) and TLS-bound tokens
    (tls_client_certificate_bound_access_tokens=true) are advertised.
    Clients must pick one binding method; advertising both invites
    confusion about which is enforced and whether the server requires
    either when both headers are absent.

  dpop.informational_exercise
    When DPoP is advertised, point the operator at how to verify the
    server actually rejects AT usage without a DPoP proof. oauthive
    ships oauthive.jose.dpop for building proofs; the live-accept test
    requires a session and a resource endpoint the operator knows
    about.

Real PoP-enforcement probing (does the server accept an AT at
/userinfo without a DPoP header when the token was bound?) is
session-dependent and lands when ctx.ensure_session() returns a
session that has a bound AT.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class DPoPCheck:
    id = "dpop"
    name = "DPoP / mTLS sender-constrained-token posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        caps = ctx.capabilities.oidc
        if not caps.present:
            return []
        findings: list[Finding] = []

        if caps.dpop_supported and caps.mtls_bound_tokens:
            findings.append(
                Finding(
                    id="dpop.advertised_with_mtls_binding",
                    severity="low",
                    confidence="high",
                    title="Server advertises both DPoP and mTLS-bound tokens",
                    description=(
                        "Two sender-constrained-token mechanisms are offered. "
                        "Clients must pick one; operators have to document "
                        "which is enforced and when. Confirm that clients "
                        "configured for DPoP actually send DPoP proofs, and "
                        "that clients configured for mTLS actually present "
                        "the client cert. A server that accepts a raw Bearer "
                        "with neither is not sender-constrained despite the "
                        "advertisement."
                    ),
                    spec_ref="RFC 9449; RFC 8705",
                    remediation=(
                        "Document the default binding method and ensure every "
                        "client is explicitly configured for one or the other."
                    ),
                    evidence={
                        "dpop_signing_algs": getattr(
                            ctx.discovery, "dpop_signing_alg_values_supported", []
                        ),
                        "tls_client_certificate_bound_access_tokens": (
                            caps.mtls_bound_tokens
                        ),
                    },
                )
            )

        if caps.dpop_supported:
            findings.append(
                Finding(
                    id="dpop.exercise_against_protected_resource",
                    severity="info",
                    confidence="high",
                    title="Exercise DPoP enforcement against a protected resource",
                    description=(
                        "Confirm your resource server actually rejects an AT "
                        "presented without a DPoP proof when that AT was "
                        "minted as sender-constrained:\n\n"
                        "  python -c 'from oauthive.jose.dpop import "
                        "generate_dpop_key, build_dpop_proof; k = "
                        "generate_dpop_key(); print(build_dpop_proof("
                        "key=k, htm=\"GET\", htu=\"<resource url>\"))'\n\n"
                        "Send the AT without the DPoP header (and with an "
                        "obviously-wrong one) to the protected resource; a "
                        "well-configured server returns 401 with "
                        "WWW-Authenticate: DPoP error=invalid_dpop_proof."
                    ),
                    spec_ref="RFC 9449 sec 4 and sec 7",
                    remediation=(
                        "Ensure the resource server: (1) requires the DPoP "
                        "header for any AT whose cnf.jkt claim is present; "
                        "(2) rejects missing or unrelated proofs; (3) checks "
                        "the proof's htm/htu/iat/jti + ath."
                    ),
                    evidence={
                        "dpop_signing_algs": getattr(
                            ctx.discovery, "dpop_signing_alg_values_supported", []
                        ),
                    },
                )
            )

        return findings
