"""SAML RelayState posture.

Metadata does not constrain RelayState handling; this check is mostly an
informational reminder that RelayState is bounded to <= 80 bytes and must
be treated as opaque, plus a placeholder for the SP-side enforcement
sub-findings (reflected unvalidated, oversized accepted) that land when we
have a live SP target via the fixture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLRelayStateCheck:
    id = "saml_relaystate"
    name = "SAML RelayState posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []

        return [
            Finding(
                id="saml_relaystate.metadata_declares_nothing",
                severity="info",
                confidence="high",
                title="RelayState integrity must be enforced out-of-band",
                description=(
                    "SAML metadata has no field to declare how RelayState is "
                    "validated. SPs must: (1) bound RelayState to <= 80 bytes; "
                    "(2) treat it as opaque and never use it as a redirect "
                    "target without an allowlist; (3) ideally integrity-protect "
                    "it with a server-side session binding. oauthive cannot "
                    "verify this from metadata alone -- exercise your SP's "
                    "ACS with an attacker-controlled RelayState to confirm."
                ),
                spec_ref="SAML 2.0 Bindings sec 3.4.3; OWASP SAMLv2 cheat sheet",
                remediation=(
                    "Enforce a strict allowlist on any post-login redirect "
                    "that uses RelayState; refuse RelayState > 80 bytes."
                ),
                evidence={"entity_id": md.entity_id},
            )
        ]
