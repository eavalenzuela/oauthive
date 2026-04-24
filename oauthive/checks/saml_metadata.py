"""SAML metadata trust posture.

- saml_metadata.fetched_over_http : source URL is plain http, so mid-flight
  substitution is trivial.
- saml_metadata.valid_until_expired : validUntil is in the past.
- saml_metadata.valid_until_absent : no validUntil at all; consumers that
  pin a stale snapshot will keep trusting rotated-away keys forever.

The `metadata_unsigned` sub-finding is already emitted by saml_assertion;
we don't duplicate it here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLMetadataCheck:
    id = "saml_metadata"
    name = "SAML metadata trust posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []
        findings: list[Finding] = []

        if md.source_url and md.source_url.startswith("http://"):
            findings.append(
                Finding(
                    id="saml_metadata.fetched_over_http",
                    severity="high",
                    confidence="high",
                    title="Metadata was fetched over plain HTTP",
                    description=(
                        "An attacker on the network path can substitute this "
                        "document during the initial fetch, pinning operator-"
                        "chosen signing certs and ACS URLs. Combined with "
                        "unsigned metadata, this leads directly to forged "
                        "assertions being trusted."
                    ),
                    spec_ref="SAML Metadata Interoperability sec 4.1",
                    remediation=(
                        "Fetch over HTTPS with hostname verification, or pin "
                        "a sha256 fingerprint of the metadata bytes."
                    ),
                    evidence={"source_url": md.source_url},
                )
            )

        if md.valid_until is None:
            findings.append(
                Finding(
                    id="saml_metadata.valid_until_absent",
                    severity="low",
                    confidence="high",
                    title="Metadata has no validUntil attribute",
                    description=(
                        "validUntil bounds how long a consumer will trust a "
                        "pinned copy. Without it, a consumer that caches once "
                        "will continue trusting rotated-away keys indefinitely "
                        "unless the operator manually refreshes."
                    ),
                    spec_ref="SAML 2.0 Metadata sec 2.2.3",
                    remediation=(
                        "Add validUntil (and optionally cacheDuration) to the "
                        "EntityDescriptor and refresh your publication pipeline "
                        "before it lapses."
                    ),
                    evidence={"entity_id": md.entity_id},
                )
            )
        else:
            now = datetime.now(timezone.utc)
            vu = md.valid_until
            if vu.tzinfo is None:
                vu = vu.replace(tzinfo=timezone.utc)
            if vu < now:
                findings.append(
                    Finding(
                        id="saml_metadata.valid_until_expired",
                        severity="medium",
                        confidence="high",
                        title="Metadata validUntil is in the past",
                        description=(
                            "Consumers that honor validUntil will refuse to "
                            "trust this document; consumers that ignore it "
                            "will keep using stale signing / encryption keys."
                        ),
                        spec_ref="SAML 2.0 Metadata sec 2.2.3",
                        remediation=(
                            "Re-publish metadata with a fresh validUntil."
                        ),
                        evidence={
                            "valid_until": vu.isoformat(),
                            "now": now.isoformat(),
                        },
                    )
                )

        return findings
