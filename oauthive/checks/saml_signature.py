"""SAML signing-cert posture (IdP-side).

What this check does NOT do: feed forged Responses to an operator's SP to
see if the SP accepts them. That is out of band -- use
`oauthive saml forge --attack strip_signature` and POST the result to your
ACS URL.

What it does: reads the IdP metadata that the runner already parsed and
reports on the signing-cert hygiene and signed-request posture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..saml.verify import (
    CertInspectionError,
    inspect_cert,
    public_key_is_weak,
    signature_alg_is_weak,
)
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class SAMLSignatureCheck:
    id = "saml_signature"
    name = "SAML signing posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []
        findings: list[Finding] = []

        if md.want_authn_requests_signed is False:
            findings.append(
                Finding(
                    id="saml_signature.want_authn_requests_signed_false",
                    severity="medium",
                    confidence="high",
                    title="IdP does not require signed AuthnRequests",
                    description=(
                        "WantAuthnRequestsSigned is False. An attacker can "
                        "send crafted AuthnRequests (e.g. with a "
                        "post-logout_redirect-style fixation value in "
                        "AssertionConsumerServiceURL) on behalf of any SP "
                        "known to this IdP."
                    ),
                    spec_ref=(
                        "SAML 2.0 Core sec 2.3; SAML 2.0 Security and Privacy "
                        "Considerations sec 6.1.5"
                    ),
                    remediation=(
                        "Set WantAuthnRequestsSigned=true and register the "
                        "SPs' signing certs so the IdP can verify."
                    ),
                    evidence={
                        "want_authn_requests_signed": md.want_authn_requests_signed,
                    },
                )
            )

        signing_certs = md.signing_certs()
        if not signing_certs and md.role in ("idp", "sp+idp", "idp+sp"):
            findings.append(
                Finding(
                    id="saml_signature.no_signing_cert",
                    severity="high",
                    confidence="high",
                    title="IdP metadata publishes no signing KeyDescriptor",
                    description=(
                        "Without a signing cert in metadata, SPs cannot verify "
                        "Response/Assertion signatures against a pinned key. "
                        "Often this means the IdP issues unsigned artifacts "
                        "or publishes keys out of band."
                    ),
                    spec_ref="SAML 2.0 Metadata sec 2.4.1.1",
                    remediation="Publish the current signing cert in KeyDescriptor use='signing'.",
                    evidence={"role": md.role},
                )
            )

        for idx, pem in enumerate(signing_certs):
            try:
                info = inspect_cert(pem)
            except CertInspectionError as e:
                findings.append(
                    Finding(
                        id=f"saml_signature.signing_cert_unparseable[{idx}]",
                        severity="medium",
                        confidence="high",
                        title="Signing cert in metadata is not parseable",
                        description=(
                            "KeyDescriptor use='signing' contains an "
                            "X509Certificate that failed to parse as a PEM "
                            f"certificate: {e}. SPs that pin against this "
                            "entry cannot verify anything."
                        ),
                        spec_ref="SAML 2.0 Metadata sec 2.4.1.1",
                        remediation="Republish a valid PEM cert.",
                        evidence={"index": idx},
                    )
                )
                continue

            if info.is_expired:
                findings.append(
                    Finding(
                        id=f"saml_signature.signing_cert_expired[{idx}]",
                        severity="high",
                        confidence="high",
                        title="Advertised signing cert is expired",
                        description=(
                            "The signing cert published in metadata is past "
                            "its NotAfter. SPs with strict clocks will reject "
                            "all signatures; lenient SPs may accept, masking "
                            "an operational gap until a signed attacker "
                            "variant slips through."
                        ),
                        spec_ref="SAML 2.0 Metadata sec 2.4.1.1; RFC 5280",
                        remediation="Rotate to a fresh signing cert.",
                        evidence={
                            "subject": info.subject,
                            "not_after": info.not_after.isoformat(),
                        },
                    )
                )

            if public_key_is_weak(info):
                findings.append(
                    Finding(
                        id=f"saml_signature.signing_key_weak[{idx}]",
                        severity="medium",
                        confidence="high",
                        title=(
                            f"Signing key below minimum recommended size "
                            f"({info.public_key_type} {info.public_key_bits})"
                        ),
                        description=(
                            "RSA signing keys should be at least 2048 bits; "
                            "EC keys at least 256 bits."
                        ),
                        spec_ref="NIST SP 800-57; OWASP ASVS 6.2",
                        remediation="Issue a new cert with a stronger key.",
                        evidence={
                            "subject": info.subject,
                            "public_key_type": info.public_key_type,
                            "public_key_bits": info.public_key_bits,
                        },
                    )
                )

            if signature_alg_is_weak(info):
                findings.append(
                    Finding(
                        id=f"saml_signature.signing_cert_weak_sig_alg[{idx}]",
                        severity="medium",
                        confidence="high",
                        title=(
                            f"Signing cert itself was signed with a weak algorithm "
                            f"({info.signature_algorithm_name or info.signature_algorithm_oid})"
                        ),
                        description=(
                            "SHA-1 (and MD5) based signatures are deprecated. "
                            "The cert's own signature chains to whatever issued it; "
                            "a cert signed with SHA-1 signals a broader legacy "
                            "posture."
                        ),
                        spec_ref="RFC 6194; NIST SP 800-131A",
                        remediation="Reissue the cert from a SHA-256 (or better) CA.",
                        evidence={
                            "subject": info.subject,
                            "sig_alg_oid": info.signature_algorithm_oid,
                        },
                    )
                )

        return findings
