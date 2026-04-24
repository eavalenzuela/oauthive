"""JOSE utilities.

- forge: hand-rolled JWS compact serialization for the malicious path
  (alg=none, HS256-with-pubkey, arbitrary kid/jku/x5u headers). PyJWT and
  python-jose both refuse to produce these variants, which is why we build
  them ourselves.
- verify: honest ID-token decode + JWKS fetching. Backed by PyJWT.
"""

from __future__ import annotations

from .forge import (
    ForgeError,
    forge_alg_none,
    forge_hs256_with_pubkey,
    forge_with_header,
    generate_attacker_rsa,
)
from .verify import (
    VerifyError,
    fetch_jwks,
    verify_id_token,
)

__all__ = [
    "ForgeError",
    "VerifyError",
    "fetch_jwks",
    "forge_alg_none",
    "forge_hs256_with_pubkey",
    "forge_with_header",
    "generate_attacker_rsa",
    "verify_id_token",
]
