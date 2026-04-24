"""XML Signature Wrapping posture.

The XSW family (XSW1-XSW8, Somorovsky et al. "On Breaking SAML") is tested
against an SP, not an IdP. An IdP issues signed Responses; it is the SP's
signature-verification logic that either survives or fails each wrapping
variant.

oauthive is IdP-facing, so this check does not probe an SP. What it can do
is *tell the operator* that XSW is a ready-to-run attack class, enumerate
the eight variants we ship a forge for, and provide the exact CLI command
each one uses. The operator drives the run against their own SP.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..saml.forge import XSW_VARIANTS
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLXSWCheck:
    id = "saml_xsw"
    name = "XML Signature Wrapping (XSW1-XSW8) exercise"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []

        variants = sorted(XSW_VARIANTS.keys())
        commands = "\n".join(
            f"  oauthive saml forge --attack {v} --from-file real-response.xml "
            f"--evil-name-id admin@victim.test"
            for v in variants
        )

        return [
            Finding(
                id="saml_xsw.exercise_against_sp",
                severity="info",
                confidence="high",
                title="Exercise XSW1-XSW8 against your SP",
                description=(
                    "XML Signature Wrapping is an SP-side defect: the verifier "
                    "signs-over one element while the business logic reads a "
                    "different element. Capture a real signed Response from "
                    "this IdP, then post each variant below to your ACS URL "
                    "and confirm your SP rejects all of them.\n\n"
                    f"{commands}"
                ),
                spec_ref=(
                    "Somorovsky et al., 'On Breaking SAML: Be Whoever You "
                    "Want to Be' (USENIX 2012); SAML Profiles sec 4.1.4"
                ),
                remediation=(
                    "Ensure the SP's verifier resolves Reference URIs strictly "
                    "and the business-logic reader traverses the *same* "
                    "element the signature covered. Many SAML libraries have "
                    "XSW-hardening modes -- enable them."
                ),
                evidence={
                    "variants": variants,
                    "idp_entity_id": md.entity_id,
                    "usage_hint": (
                        "capture a real Response with `oauthive saml decode "
                        "/path/to/sso-capture` first"
                    ),
                },
            )
        ]
