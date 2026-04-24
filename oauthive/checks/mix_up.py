"""Mix-up / dynamic-registration posture.

OAuth 2.0 Security BCP sec 4.4: mix-up attacks trick an RP (often one that
federates multiple IdPs) into treating a response from IdP B as if it came
from IdP A. Defenses include RFC 9207 (iss in authorization response), strict
IdP selection bound to session state, and exact-match redirect_uri policy.

What we can probe here from the IdP side:

- dynamic_registration.anonymous_accepted : anonymous POST to the
  registration_endpoint (RFC 7591) is accepted, letting an attacker register
  a malicious client at this IdP on the fly. Combined with a permissive RP,
  this is the bread and butter of mix-up attacks.

- dynamic_registration.jwks_uri_unvalidated : the IdP lets a new client
  register a jwks_uri at a host the IdP does not own. Tokens signed by a
  key the attacker controls then validate at this IdP (RFC 7591 sec 3.1
  says the IdP SHOULD validate client_id ownership / key ownership).

- mix_up.iss_not_returned is *also* covered in state.py and only reported
  there; this check sticks to dynamic-registration probes.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class MixUpCheck:
    id = "mix_up"
    name = "mix-up defense / dynamic registration"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        if ctx.discovery is None:
            return []
        findings: list[Finding] = []

        reg = ctx.discovery.registration_endpoint
        if reg is None:
            return findings

        # Anonymous registration probe.
        candidate_name = f"oauthive-mixup-probe-{secrets.token_hex(4)}"
        payload = {
            "client_name": candidate_name,
            "redirect_uris": ["https://localhost:8443/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        try:
            resp = await ctx.http.post(
                str(reg),
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:  # noqa: BLE001
            ctx.log.warning("mix_up.registration_probe_failed", error=str(e))
            return findings

        if 200 <= resp.status_code < 300:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            client_id = body.get("client_id")
            findings.append(
                Finding(
                    id="dynamic_registration.anonymous_accepted",
                    severity="high",
                    confidence="high",
                    title="Anonymous client registration is accepted",
                    description=(
                        "The discovery document advertises a registration "
                        "endpoint and it issued a client_id to an anonymous "
                        "POST. RPs that federate this IdP may be willing to "
                        "accept tokens from the attacker-registered client, "
                        "and it's the typical starting point for mix-up and "
                        "client confusion attacks."
                    ),
                    spec_ref="RFC 7591 sec 3; OAuth 2.0 Security BCP sec 4.4",
                    remediation=(
                        "Require an initial access token (RFC 7591 sec 3.1) "
                        "or disable dynamic registration for production tenants."
                    ),
                    evidence={
                        "assigned_client_id": client_id,
                        "registration_response_keys": sorted(body.keys())
                        if isinstance(body, dict)
                        else [],
                    },
                )
            )

            # If registration lets us set a jwks_uri pointing at an attacker
            # host, that's the more dangerous follow-up. Probe with a fresh
            # payload; many servers tolerate missing fields but reject unknown
            # ones.
            evil_jwks = "https://evil.example.test/jwks.json"
            payload2 = {
                **payload,
                "client_name": f"{candidate_name}-jwks",
                "jwks_uri": evil_jwks,
                "token_endpoint_auth_method": "private_key_jwt",
            }
            try:
                resp2 = await ctx.http.post(
                    str(reg),
                    json=payload2,
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:  # noqa: BLE001
                ctx.log.warning("mix_up.jwks_probe_failed", error=str(e))
                resp2 = None

            if resp2 is not None and 200 <= resp2.status_code < 300:
                try:
                    body2 = resp2.json()
                except ValueError:
                    body2 = {}
                if body2.get("jwks_uri") == evil_jwks:
                    findings.append(
                        Finding(
                            id="dynamic_registration.jwks_uri_unvalidated",
                            severity="critical",
                            confidence="high",
                            title="Dynamic registration accepts attacker-hosted jwks_uri",
                            description=(
                                "The registration endpoint accepted a jwks_uri "
                                "pointing at a host the operator does not "
                                "control. Tokens signed by the attacker's keys "
                                "and presented with this client_id validate "
                                "here, breaking the trust model entirely."
                            ),
                            spec_ref="RFC 7591 sec 3.1; RFC 8705 sec 2 (by analogy)",
                            remediation=(
                                "Reject registration requests whose jwks_uri is "
                                "not owned by the registering party, or require "
                                "out-of-band proof of control."
                            ),
                            evidence={
                                "registered_jwks_uri": body2.get("jwks_uri"),
                                "assigned_client_id": body2.get("client_id"),
                            },
                        )
                    )

        return findings
