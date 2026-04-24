"""DPoP (RFC 9449) proof-of-possession utility.

Build a DPoP proof JWT for a given HTTP request. The resulting token is sent
in the `DPoP` header when calling protected endpoints. oauthive uses this
for checks that want to observe whether a server actually enforces DPoP
(e.g. sends an access token without a DPoP proof and sees if it's accepted).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .forge import _b64u, _b64u_json, RSASigner


class DPoPError(RuntimeError):
    pass


@dataclass
class DPoPKey:
    """Wraps a keypair + its JWK (public half) for DPoP."""

    private_key: Any  # RSAPrivateKey | EllipticCurvePrivateKey
    jwk: dict[str, Any]
    alg: str


def generate_dpop_key(alg: str = "ES256") -> DPoPKey:
    """Mint a fresh DPoP keypair. ES256 by default -- DPoP servers MUST accept
    it (RFC 9449 sec 4.2) and its JWK is compact."""
    if alg == "ES256":
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        numbers = pub.public_numbers()
        x = numbers.x.to_bytes(32, "big")
        y = numbers.y.to_bytes(32, "big")
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u(x),
            "y": _b64u(y),
        }
    elif alg == "RS256":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        n = pub.public_numbers().n
        e = pub.public_numbers().e
        jwk = {
            "kty": "RSA",
            "n": _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big")),
            "e": _b64u(e.to_bytes((e.bit_length() + 7) // 8, "big")),
        }
    else:
        raise DPoPError(f"unsupported alg {alg!r} (use ES256 or RS256)")
    return DPoPKey(private_key=priv, jwk=jwk, alg=alg)


def build_dpop_proof(
    *,
    key: DPoPKey,
    htm: str,
    htu: str,
    access_token: str | None = None,
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    """Build a DPoP proof JWT. `htm` is the HTTP method (uppercase); `htu` is
    the target URL without query/fragment. When `access_token` is given, the
    resulting proof includes the `ath` claim that binds it to that AT
    (RFC 9449 sec 4.2)."""
    header = {"typ": "dpop+jwt", "alg": key.alg, "jwk": key.jwk}
    claims: dict[str, Any] = {
        "htm": htm.upper(),
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti or secrets.token_urlsafe(16),
    }
    if access_token is not None:
        ath = hashlib.sha256(access_token.encode()).digest()
        claims["ath"] = _b64u(ath)

    signing_input = f"{_b64u_json(header)}.{_b64u_json(claims)}".encode()
    if key.alg == "RS256":
        sig = RSASigner(key.private_key).sign(signing_input)
    elif key.alg == "ES256":
        from cryptography.hazmat.primitives import hashes as _h
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        der = key.private_key.sign(signing_input, ec.ECDSA(_h.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise DPoPError(f"unsupported alg {key.alg!r}")

    return f"{_b64u_json(header)}.{_b64u_json(claims)}.{_b64u(sig)}"
