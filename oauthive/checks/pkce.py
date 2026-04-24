"""PKCE (RFC 7636) posture.

Passive probes against /authorize. We look for:
  - PKCE not enforced for public clients (no code_challenge is accepted).
  - 'plain' code_challenge_method accepted when S256 is advertised.
  - Malformed code_challenge accepted (no shape validation).

Verifier reuse across exchanges and missing-verifier-accepted-at-/token are
deeper checks that require a live code exchange; when ctx.session_factory is
wired and the test driver can produce a real code, those sub-findings land.
For now (passive-only), this check flags the cases observable at /authorize.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..client import generate_pkce_pair
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class PKCECheck:
    id = "pkce"
    name = "PKCE enforcement"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            return []

        findings: list[Finding] = []
        advertises_pkce = bool(ctx.capabilities.oidc.pkce_methods)

        # (1) Is PKCE required? Probe without any code_challenge.
        no_pkce = await client.probe_authorization()
        if no_pkce.accepted_redirect:
            # IdP was willing to redirect us to the app with no code_challenge.
            # For public clients RFC 7636 sec 4.4.1 and OAuth 2.1 both require PKCE.
            findings.append(
                Finding(
                    id="pkce.not_required",
                    severity="high",
                    confidence="high",
                    title="PKCE not required at /authorize",
                    description=(
                        "The authorization endpoint accepted a request with no "
                        "code_challenge parameter. Public (non-confidential) clients "
                        "must use PKCE per OAuth 2.1 and RFC 7636 sec 4.4.1; "
                        "confidential clients should also enforce it as defense in "
                        "depth against stolen authorization codes."
                    ),
                    spec_ref="RFC 7636 sec 4.4.1; OAuth 2.1 draft sec 4.1.1",
                    poc_url=no_pkce.location,
                    remediation=(
                        "Configure the IdP / client to require code_challenge on "
                        "this client. If this client is registered as confidential "
                        "yet does not use client authentication (public app), "
                        "reclassify and enforce PKCE."
                    ),
                    evidence={
                        "status_code": no_pkce.status_code,
                        "location": no_pkce.location,
                    },
                )
            )

        # (2) 'plain' method accepted?
        _, challenge = generate_pkce_pair()  # S256 challenge value
        plain_resp = await client.probe_authorization(
            extra={
                "code_challenge": challenge,
                "code_challenge_method": "plain",
            }
        )
        if plain_resp.accepted_redirect and advertises_pkce:
            advertises_plain = "plain" in ctx.capabilities.oidc.pkce_methods
            if not advertises_plain:
                findings.append(
                    Finding(
                        id="pkce.plain_accepted_when_not_advertised",
                        severity="medium",
                        confidence="high",
                        title="'plain' PKCE method accepted despite not being advertised",
                        description=(
                            "Discovery advertises PKCE methods but does not include "
                            "'plain'; the authorization endpoint accepted it anyway. "
                            "'plain' exposes the code_verifier to anyone who can read "
                            "the authorization request; S256 should be enforced."
                        ),
                        spec_ref="RFC 7636 sec 4.2; OAuth 2.0 Security BCP sec 2.1.1",
                        poc_url=plain_resp.location,
                        remediation=(
                            "Reject code_challenge_method values other than S256 at "
                            "this client; remove 'plain' support entirely if no "
                            "legacy client requires it."
                        ),
                        evidence={
                            "advertised_methods": ctx.capabilities.oidc.pkce_methods,
                        },
                    )
                )
            elif "plain" in ctx.capabilities.oidc.pkce_methods:
                findings.append(
                    Finding(
                        id="pkce.plain_supported",
                        severity="medium",
                        confidence="high",
                        title="'plain' PKCE method is advertised and accepted",
                        description=(
                            "'plain' code_challenge_method provides no protection "
                            "against an attacker who observes the authorization "
                            "request -- the verifier equals the challenge. Only "
                            "S256 should be supported."
                        ),
                        spec_ref="RFC 7636 sec 4.2; OAuth 2.1 draft sec 7.5",
                        poc_url=plain_resp.location,
                        remediation="Remove 'plain' from code_challenge_methods_supported.",
                        evidence={
                            "advertised_methods": ctx.capabilities.oidc.pkce_methods,
                        },
                    )
                )

        # (3) Malformed challenge accepted? S256 requires base64url-no-pad, 43 chars.
        malformed = "not-a-valid-challenge!"
        mal_resp = await client.probe_authorization(
            extra={
                "code_challenge": malformed,
                "code_challenge_method": "S256",
            }
        )
        if mal_resp.accepted_redirect:
            findings.append(
                Finding(
                    id="pkce.malformed_challenge_accepted",
                    severity="low",
                    confidence="medium",
                    title="Malformed code_challenge accepted at /authorize",
                    description=(
                        "The authorization endpoint accepted a code_challenge that "
                        "is not a 43-char base64url(sha256) value. The IdP may be "
                        "storing the challenge without validation and later "
                        "comparing against the verifier by simple string equality, "
                        "which opens the door to challenge-method confusion."
                    ),
                    spec_ref="RFC 7636 sec 4.2",
                    poc_url=mal_resp.location,
                    remediation=(
                        "Validate code_challenge shape at /authorize (length 43, "
                        "base64url alphabet, no padding) and reject anything else."
                    ),
                    evidence={"malformed_challenge": malformed},
                )
            )

        return findings
