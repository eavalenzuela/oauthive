"""SAML assertion-enforcement posture.

Metadata-level posture only at M11. Live enforcement (NotBefore drift,
Recipient mismatch, replay window, etc.) is tested out of band by feeding
forged variants to the operator's SP via `oauthive saml forge`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLAssertionCheck:
    id = "saml_assertion"
    name = "SAML assertion enforcement posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []
        findings: list[Finding] = []

        if "sp" in md.role and md.want_assertions_signed is False:
            findings.append(
                Finding(
                    id="saml_assertion.want_assertions_signed_false",
                    severity="medium",
                    confidence="high",
                    title="SP metadata does not require signed assertions",
                    description=(
                        "WantAssertionsSigned=false means the SP will accept "
                        "assertions that are signed only at the Response wrapper "
                        "(or not at all). Some IdPs sign only one or the other; "
                        "the strictest posture requires assertions themselves to "
                        "be signed so XML Signature Wrapping variants have less "
                        "to grab onto."
                    ),
                    spec_ref="SAML 2.0 Profiles sec 4.1.4.3; SAML 2.0 Metadata sec 2.4.2",
                    remediation="Set WantAssertionsSigned=true on the SP.",
                    evidence={"want_assertions_signed": md.want_assertions_signed},
                )
            )

        if md.metadata_signed is False:
            findings.append(
                Finding(
                    id="saml_assertion.metadata_unsigned",
                    severity="low",
                    confidence="high",
                    title="Metadata document itself is not signed",
                    description=(
                        "Unsigned metadata can be replaced in transit if the "
                        "consuming party fetches it over HTTP or does not pin "
                        "a fingerprint. With attacker-swapped metadata, the "
                        "consumer trusts attacker-chosen signing certs + ACS "
                        "URLs."
                    ),
                    spec_ref="SAML 2.0 Metadata sec 2.1; SAML Metadata IOP sec 4",
                    remediation=(
                        "Sign the EntityDescriptor with a long-lived key and "
                        "document a pinned fingerprint for consumers."
                    ),
                    evidence={"entity_id": md.entity_id},
                )
            )

        return findings
