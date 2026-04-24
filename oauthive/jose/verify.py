"""Honest ID-token verification.

Thin wrapper around PyJWT + a JWKS fetcher. Used by the id_token check when
a real token is available (via the browser driver) so we can inspect what
the IdP actually issued.

`unsafe_decode` is here for exploring a token without validation; it does
not verify any signature and must never be used to establish trust.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt


class VerifyError(RuntimeError):
    pass


@dataclass
class DecodedToken:
    header: dict[str, Any]
    claims: dict[str, Any]
    signature_b64: str


def _b64u_pad(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def unsafe_decode(token: str) -> DecodedToken:
    """Split and parse without verifying. Raises VerifyError on malformed input."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError as e:
        raise VerifyError(f"token is not a compact JWS: {e}") from e
    try:
        header = json.loads(_b64u_pad(h_b64))
        claims = json.loads(_b64u_pad(p_b64))
    except (ValueError, UnicodeDecodeError) as e:
        raise VerifyError(f"header/claims not valid JSON: {e}") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise VerifyError("header/claims must be JSON objects")
    return DecodedToken(header=header, claims=claims, signature_b64=s_b64)


async def fetch_jwks(jwks_uri: str, *, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    own = client is None
    c = client or httpx.AsyncClient(timeout=10.0)
    try:
        resp = await c.get(jwks_uri, headers={"Accept": "application/json"})
    except httpx.HTTPError as e:
        raise VerifyError(f"jwks fetch failed: {e}") from e
    finally:
        if own:
            await c.aclose()
    if resp.status_code != 200:
        raise VerifyError(f"jwks fetch got status {resp.status_code}")
    try:
        doc = resp.json()
    except ValueError as e:
        raise VerifyError(f"jwks is not JSON: {e}") from e
    if not isinstance(doc, dict) or "keys" not in doc:
        raise VerifyError("jwks document missing 'keys'")
    return doc


def verify_id_token(
    token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
    leeway_s: float = 5.0,
) -> dict[str, Any]:
    """Verify signature + iss + aud + exp + iat. Returns the claims on success.

    Raises VerifyError with a specific failure reason. The id_token check uses
    the failure reason to decide which IdP-side finding, if any, to emit.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise VerifyError(f"invalid token header: {e}") from e
    kid = header.get("kid")
    alg = header.get("alg")
    if alg in (None, "none", "None"):
        raise VerifyError(f"token alg={alg!r} is unacceptable")
    matching = [k for k in jwks["keys"] if (not kid or k.get("kid") == kid)]
    if not matching:
        raise VerifyError(f"no JWKS key matches kid={kid!r}")
    last_err: Exception | None = None
    for k in matching:
        try:
            pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
        try:
            return jwt.decode(
                token,
                pub,
                algorithms=[alg],
                audience=audience,
                issuer=issuer,
                leeway=leeway_s,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.InvalidTokenError as e:
            last_err = e
            continue
    raise VerifyError(f"no key validated: {last_err}")


def inspect_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Lightweight hygiene summary for an ID token. Caller decides what to do.

    Keys returned:
      - has_iss / has_aud / has_exp / has_iat / has_sub / has_nonce
      - exp_in_past (None if no exp)
      - iat_far_future (None if no iat)
    """
    now = time.time()
    exp = claims.get("exp")
    iat = claims.get("iat")
    return {
        "has_iss": "iss" in claims,
        "has_aud": "aud" in claims,
        "has_exp": "exp" in claims,
        "has_iat": "iat" in claims,
        "has_sub": "sub" in claims,
        "has_nonce": "nonce" in claims,
        "exp_in_past": (exp < now) if isinstance(exp, (int, float)) else None,
        "iat_far_future": (iat > now + 600) if isinstance(iat, (int, float)) else None,
    }
