"""XXE / DTD / entity posture of the IdP's AuthnRequest parser.

Unlike XSW and the comment-injection attacks, XXE is IdP-side: an attacker
posts a crafted AuthnRequest to the IdP's SSO endpoint and observes how its
XML parser reacts. Modern SAML stacks (python-saml, Keycloak's stax parser,
ADFS) are resistant, but custom-rolled implementations and legacy stacks
sometimes are not.

Exposing an IdP to a billion-laughs or a large OOB-entity chain can cause
a real denial of service, so oauthive does not ship an active probe here.
Instead the check enumerates the attack variants and points the operator
at `oauthive saml forge` with bounded payloads plus a running malicious_rp
for OOB collection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLXXECheck:
    id = "saml_xxe"
    name = "XXE / DTD / entity exercise for the IdP's parser"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []

        ssos = [f"{s.location} ({s.binding.rsplit(':', 1)[-1]})" for s in md.sso_services]

        return [
            Finding(
                id="saml_xxe.exercise_against_idp",
                severity="info",
                confidence="high",
                title="Exercise XXE / DTD / entity handling against your IdP",
                description=(
                    "Three variants ship with `oauthive saml forge` -- build "
                    "each, then POST the body (or redirect-b64 encode it) to "
                    "an SSO endpoint advertised in metadata, and observe.\n\n"
                    "  oauthive saml forge --attack xxe_external_entity "
                    "--oob-url https://<malicious_rp>/cb "
                    "--issuer <your sp> --acs-url <acs> "
                    "--destination <sso-endpoint>\n"
                    "  oauthive saml forge --attack xxe_parameter_entity ...\n"
                    "  oauthive saml forge --attack xxe_bounded_expansion ...\n\n"
                    "External/parameter-entity probes are OOB: run "
                    "`oauthive fixture up` (or your own listener) beforehand "
                    "and inspect its captures. Bounded-expansion probes are "
                    "local: time the IdP's response; disproportionate latency "
                    "indicates entity expansion is enabled."
                ),
                spec_ref=(
                    "OWASP XXE cheat sheet; SAML 2.0 Bindings sec 3.1 "
                    "(does not mandate DTD rejection, but every safe parser "
                    "refuses it in practice)"
                ),
                remediation=(
                    "Ensure the IdP's XML parser runs with DTD loading, "
                    "external entities, and parameter entities disabled. "
                    "In Java, StAX / DOM factories expose XMLConstants "
                    "features; in .NET, XmlReaderSettings.DtdProcessing. "
                    "NEVER run an XML billion-laughs against a production "
                    "IdP."
                ),
                evidence={"idp_entity_id": md.entity_id, "sso_endpoints": ssos},
            )
        ]
