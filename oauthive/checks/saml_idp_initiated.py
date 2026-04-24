"""IdP-initiated (unsolicited) Response posture.

Metadata cannot say whether an IdP or SP supports unsolicited Responses;
the SAML Web Browser SSO profile makes it an IdP option and an SP policy
question. This check is informational: it reminds the operator that IdP-
initiated acceptance on the SP is a security-relevant toggle, and tags the
finding with the entity so a demo / vuln-SP run can cross-reference.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLIdPInitiatedCheck:
    id = "saml_idp_initiated"
    name = "SAML IdP-initiated posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []

        return [
            Finding(
                id="saml_idp_initiated.requires_sp_posture_check",
                severity="info",
                confidence="high",
                title=(
                    "IdP-initiated (unsolicited) Response handling is not "
                    "observable from metadata"
                ),
                description=(
                    "Unsolicited Responses have no outstanding AuthnRequest "
                    "and therefore no InResponseTo to validate. Whether your "
                    "SP accepts them is a policy choice that typically lives "
                    "in SP configuration, not IdP metadata. Use "
                    "`oauthive saml forge` to build an unsolicited Response "
                    "and verify your SP either: (a) refuses; or (b) accepts "
                    "only when the policy explicitly allows, with a strict "
                    "NameID/Audience match."
                ),
                spec_ref="SAML 2.0 Profiles sec 4.1.3.5",
                remediation=(
                    "Explicitly configure your SP to refuse unsolicited "
                    "Responses unless a business requirement documents "
                    "otherwise."
                ),
                evidence={"entity_id": md.entity_id, "role": md.role},
            )
        ]
