
import httpx
import pytest
import respx

from oauthive.jose.forge import RSASigner, forge_with_header, generate_attacker_rsa
from oauthive.jose.verify import VerifyError, fetch_jwks, inspect_claims, unsafe_decode, verify_id_token


def test_unsafe_decode_happy_path():
    priv, _pub, jwk = generate_attacker_rsa()
    token = forge_with_header(
        {"sub": "x", "aud": "rp", "iss": "https://idp"},
        {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]},
        RSASigner(priv),
    )
    d = unsafe_decode(token)
    assert d.header["kid"] == jwk["kid"]
    assert d.claims["sub"] == "x"


def test_unsafe_decode_malformed():
    with pytest.raises(VerifyError):
        unsafe_decode("not-a-jwt")


def test_unsafe_decode_non_json():
    # Valid base64url but not JSON
    import base64 as _b

    bad = _b.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
    with pytest.raises(VerifyError):
        unsafe_decode(f"{bad}.{bad}.")


@respx.mock
async def test_fetch_jwks_happy():
    respx.get("https://idp.example.com/jwks.json").mock(
        return_value=httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "a"}]})
    )
    doc = await fetch_jwks("https://idp.example.com/jwks.json")
    assert doc["keys"][0]["kid"] == "a"


@respx.mock
async def test_fetch_jwks_404():
    respx.get("https://idp.example.com/jwks.json").mock(
        return_value=httpx.Response(404, text="nope")
    )
    with pytest.raises(VerifyError, match="status"):
        await fetch_jwks("https://idp.example.com/jwks.json")


@respx.mock
async def test_fetch_jwks_not_json():
    respx.get("https://idp.example.com/jwks.json").mock(
        return_value=httpx.Response(200, text="<html/>")
    )
    with pytest.raises(VerifyError):
        await fetch_jwks("https://idp.example.com/jwks.json")


def test_verify_id_token_rejects_alg_none():
    from oauthive.jose.forge import forge_alg_none

    token = forge_alg_none({"sub": "x", "aud": "rp", "iss": "https://idp", "exp": 9999999999, "iat": 0})
    with pytest.raises(VerifyError, match="none"):
        verify_id_token(
            token, jwks={"keys": []}, issuer="https://idp", audience="rp"
        )


def test_verify_id_token_happy_path():
    priv, _pub, jwk = generate_attacker_rsa()
    import time as _time

    now = int(_time.time())
    token = forge_with_header(
        {
            "sub": "s",
            "aud": "rp",
            "iss": "https://idp",
            "exp": now + 300,
            "iat": now,
        },
        {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]},
        RSASigner(priv),
    )
    claims = verify_id_token(
        token,
        jwks={"keys": [jwk]},
        issuer="https://idp",
        audience="rp",
    )
    assert claims["sub"] == "s"


def test_inspect_claims():
    out = inspect_claims({"iss": "x", "aud": "y"})
    assert out == {
        "has_iss": True,
        "has_aud": True,
        "has_exp": False,
        "has_iat": False,
        "has_sub": False,
        "has_nonce": False,
        "exp_in_past": None,
        "iat_far_future": None,
    }
