"""Honest SAML signature verification + cert inspection helpers.

Kept separate from the SP module so checks that want to reason about the
IdP's *cert hygiene* (key size, expiry, signature alg) don't need to drag
the full SP machinery in.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class CertInspectionError(RuntimeError):
    pass


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    public_key_type: str  # 'RSA' | 'EC' | 'other'
    public_key_bits: int | None
    signature_algorithm_oid: str
    signature_algorithm_name: str | None
    is_expired: bool
    is_self_signed: bool


def inspect_cert(pem: str | bytes) -> CertInfo:
    """Load a PEM-encoded cert and summarize. Raises on malformed input."""
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        cert = x509.load_pem_x509_certificate(data)
    except Exception as e:  # noqa: BLE001
        raise CertInspectionError(f"failed to load cert: {e}") from e

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        kty, bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        kty, bits = "EC", pub.curve.key_size
    else:
        kty, bits = "other", None

    # not_valid_before/after are deprecated in cryptography 42; use *_utc.
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=nb,
        not_after=na,
        public_key_type=kty,
        public_key_bits=bits,
        signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
        signature_algorithm_name=getattr(cert.signature_algorithm_oid, "_name", None),
        is_expired=na < datetime.now(timezone.utc),
        is_self_signed=cert.issuer == cert.subject,
    )


WEAK_SIG_ALGS = {
    "1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.4",  # md5WithRSAEncryption
    "1.2.840.10040.4.3",     # DSA with SHA1
    "1.2.840.10045.4.1",     # ECDSA with SHA1
}


def signature_alg_is_weak(info: CertInfo) -> bool:
    return info.signature_algorithm_oid in WEAK_SIG_ALGS


def public_key_is_weak(info: CertInfo) -> bool:
    if info.public_key_type == "RSA" and info.public_key_bits is not None:
        return info.public_key_bits < 2048
    if info.public_key_type == "EC" and info.public_key_bits is not None:
        return info.public_key_bits < 256
    return False
