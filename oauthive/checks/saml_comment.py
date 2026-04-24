"""NameID comment-injection exercise.

CVE-2018-0489 / similar: a signed assertion whose NameID text is
<NameID>victim@real<!---->.attacker.test</NameID> canonicalizes to
'victim@real.attacker.test' for signature verification but many SP libraries
then read the NameID text via a getText()/.content path that stops at the
first comment node, yielding 'victim@real'. The attacker thus takes over
any account at victim@real.

Like XSW, this is an SP-side defect; oauthive provides the forge primitive
and enumerates the reproducer for the operator.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLCommentCheck:
    id = "saml_comment"
    name = "NameID comment-injection exercise"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []

        return [
            Finding(
                id="saml_comment.exercise_against_sp",
                severity="info",
                confidence="high",
                title="Exercise NameID comment-injection against your SP",
                description=(
                    "Capture a real signed Response, then produce two "
                    "variants and POST each to your ACS:\n\n"
                    "  oauthive saml forge --attack inject_nameid_comment "
                    "--from-file real.xml --victim admin@yourco.test\n"
                    "  oauthive saml forge --attack inject_nameid_attribute "
                    "--from-file real.xml --victim admin@yourco.test\n\n"
                    "A well-configured SP must refuse both: its NameID "
                    "reader has to behave identically to the canonicalizer "
                    "that fed the signature."
                ),
                spec_ref=(
                    "CVE-2018-0489 / CVE-2017-11427 family; "
                    "OneLogin advisory 'SAML XML text-node exploit'"
                ),
                remediation=(
                    "Update SAML libraries to versions that refuse a NameID "
                    "containing child nodes. Duo's Duo-Labs SAML raider has a "
                    "ready-made test suite if you want coverage beyond what "
                    "oauthive ships."
                ),
                evidence={"idp_entity_id": md.entity_id},
            )
        ]
