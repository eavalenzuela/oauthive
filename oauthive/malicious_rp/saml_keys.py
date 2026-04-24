"""Malicious SP signing keypair + metadata generator.

Mirrors malicious_rp/certs.py: never auto-generates silently. When keys are
absent and no confirm callable is supplied, raises.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .certs import CertError


@dataclass
class SAMLKeyPaths:
    key: Path
    cert: Path

    def exist(self) -> bool:
        return self.key.exists() and self.cert.exists()


def default_saml_paths(base: Path | None = None) -> SAMLKeyPaths:
    base = base or Path.home() / ".oauthive" / "saml"
    return SAMLKeyPaths(key=base / "sp.key", cert=base / "sp.crt")


def ensure_saml_keys(
    paths: SAMLKeyPaths,
    *,
    cn: str = "oauthive-malicious-sp",
    confirm: Callable[[str], bool] | None = None,
) -> SAMLKeyPaths:
    """Return a usable SAMLKeyPaths, generating if necessary (with confirmation)."""
    if paths.exist():
        return paths
    prompt = (
        f"[oauthive] Generate malicious-SP keypair at {paths.cert} (CN={cn})? "
        "The cert never leaves your host unless you publish the SP's metadata."
    )
    if confirm is None or not confirm(prompt):
        raise CertError(
            "refused to generate SP keypair without explicit confirmation."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    paths.cert.parent.mkdir(parents=True, exist_ok=True)
    paths.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths.key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths.cert.chmod(0o600)
    paths.key.chmod(0o600)
    return paths


def cert_b64(paths: SAMLKeyPaths) -> str:
    """Return the certificate's base64 DER body (the shape SAML metadata wants)."""
    pem = paths.cert.read_bytes()
    # Strip PEM markers and whitespace.
    text = pem.decode()
    lines = [
        l for l in text.splitlines() if l and "BEGIN CERTIFICATE" not in l and "END CERTIFICATE" not in l
    ]
    return "".join(lines)


def build_sp_metadata(
    paths: SAMLKeyPaths,
    *,
    entity_id: str,
    acs_url: str,
    sls_url: str | None = None,
    want_assertions_signed: bool = True,
) -> bytes:
    """Build SP metadata XML. Unsigned by default; sign via an external tool
    if you need md:Signature."""
    cert = cert_b64(paths)
    sls = (
        f'    <md:SingleLogoutService '
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{sls_url}"/>'
        if sls_url
        else ""
    )
    xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="true"
                      WantAssertionsSigned="{'true' if want_assertions_signed else 'false'}"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs_url}" index="0" isDefault="true"/>
{sls}
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return xml.encode()
