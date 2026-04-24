"""SAML Assertion encryption posture.

Metadata-side: do the advertised EncryptionMethod algorithms include known-
weak choices (rsa-1_5 key wrap, CBC block cipher modes)? Is the encryption
KeyDescriptor present at all on the SP's metadata, and is its public key
strong?

SP-side: does the SP accept a plaintext Assertion when metadata advertises
WantAssertionsEncrypted? Does it surface verbose decrypt errors that would
enable a Bleichenbacher-style padding-oracle? Those require a live SP
target; we enumerate the reproducers via `oauthive saml forge`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..saml.verify import (
    CertInspectionError,
    inspect_cert,
    public_key_is_weak,
)
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


RSA_1_5_WRAP = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
CBC_MODES = {
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
}


class SAMLEncryptionCheck:
    id = "saml_encryption"
    name = "SAML assertion encryption posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"saml"})

    async def run(self, ctx: "Context") -> list[Finding]:
        md = getattr(ctx, "saml_metadata", None)
        if md is None:
            return []
        findings: list[Finding] = []

        methods = md.encryption_methods()
        if RSA_1_5_WRAP in methods:
            findings.append(
                Finding(
                    id="saml_encryption.rsa_1_5_wrap_advertised",
                    severity="high",
                    confidence="high",
                    title="rsa-1_5 key-wrap algorithm advertised",
                    description=(
                        "Metadata's KeyDescriptor advertises rsa-1_5 for key "
                        "wrapping. rsa-1_5 is vulnerable to Bleichenbacher-"
                        "style chosen-ciphertext attacks when the decryptor "
                        "surfaces any observable difference between good and "
                        "bad padding. Move to RSA-OAEP (rsa-oaep-mgf1p or "
                        "RSA-OAEP with SHA-256+)."
                    ),
                    spec_ref=(
                        "RFC 3218 / W3C XML Encryption Syntax and Processing sec 5.2; "
                        "Bleichenbacher 1998"
                    ),
                    remediation=(
                        "Remove rsa-1_5 from advertised EncryptionMethod. Keep "
                        "rsa-oaep-mgf1p at minimum; prefer RSA-OAEP with SHA-256."
                    ),
                    evidence={"advertised_methods": methods},
                )
            )

        cbc = [m for m in methods if m in CBC_MODES]
        if cbc:
            findings.append(
                Finding(
                    id="saml_encryption.cbc_mode_advertised",
                    severity="low",
                    confidence="high",
                    title="CBC-mode block cipher advertised for Assertion encryption",
                    description=(
                        "AES-CBC / 3DES-CBC combined with poorly-sealed error "
                        "surfaces permits padding-oracle recovery of assertion "
                        "plaintext. AES-GCM (aes128-gcm / aes256-gcm) is an "
                        "authenticated-encryption alternative that resists this "
                        "class of attack."
                    ),
                    spec_ref="W3C XML Encryption 1.1 sec 5.2",
                    remediation=(
                        "Advertise and prefer GCM modes; retire CBC entries "
                        "unless a legacy SP requires them (and it usually "
                        "doesn't)."
                    ),
                    evidence={"cbc_methods": cbc},
                )
            )

        for idx, pem in enumerate(md.encryption_certs()):
            try:
                info = inspect_cert(pem)
            except CertInspectionError:
                continue
            if public_key_is_weak(info):
                findings.append(
                    Finding(
                        id=f"saml_encryption.encryption_key_weak[{idx}]",
                        severity="medium",
                        confidence="high",
                        title=(
                            f"Encryption key below minimum recommended size "
                            f"({info.public_key_type} {info.public_key_bits})"
                        ),
                        description=(
                            "RSA encryption keys should be at least 2048 bits. "
                            "Short keys allow fewer work factors to recover "
                            "session material if the decryptor is also subtly "
                            "broken."
                        ),
                        spec_ref="NIST SP 800-57",
                        remediation="Reissue the encryption cert with a stronger key.",
                        evidence={
                            "subject": info.subject,
                            "public_key_bits": info.public_key_bits,
                        },
                    )
                )

        # Pointer for SP-side exercise: encryption-downgrade, verbose errors.
        findings.append(
            Finding(
                id="saml_encryption.exercise_against_sp",
                severity="info",
                confidence="high",
                title="Exercise encryption-downgrade and verbose-error handling against your SP",
                description=(
                    "Capture a real EncryptedAssertion Response from this IdP, "
                    "then: (1) strip the EncryptedAssertion and inject the "
                    "plaintext Assertion from the same flow using "
                    "`oauthive saml forge --attack strip_signature` on your "
                    "decrypted capture; POST to your SP's ACS and verify it "
                    "refuses. (2) send malformed ciphertext and observe "
                    "whether the SP's error response differs between good/bad "
                    "padding -- any such difference is a padding-oracle."
                ),
                spec_ref="OWASP SAML cheat sheet; Sec Toolbelt - SAML raider",
                remediation=(
                    "Constant-time error handling; WantAssertionsEncrypted=true "
                    "on the SP; refuse plaintext fallbacks."
                ),
                evidence={"entity_id": md.entity_id},
            )
        )

        return findings
