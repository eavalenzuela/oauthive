"""Tests for M15: DPoP proofs, mTLS wiring, Playwright polish, version bump."""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
import respx
import structlog
from cryptography.hazmat.primitives.asymmetric import ec

import oauthive
from oauthive.capabilities import CapabilitiesReport, OIDCCapabilities
from oauthive.checks.dpop import DPoPCheck
from oauthive.client import OAuthClient
from oauthive.context import Context
from oauthive.discovery import DiscoveryDoc
from oauthive.jose.dpop import DPoPError, build_dpop_proof, generate_dpop_key
from oauthive.runner import RunnerConfig, run


def _b64u_pad(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


DOC = DiscoveryDoc.model_validate(
    {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
    }
)


# ---------- DPoP ----------


def test_dpop_key_generation_es256_has_jwk():
    key = generate_dpop_key("ES256")
    assert key.alg == "ES256"
    assert key.jwk["kty"] == "EC" and key.jwk["crv"] == "P-256"
    assert "x" in key.jwk and "y" in key.jwk
    assert isinstance(key.private_key, ec.EllipticCurvePrivateKey)


def test_dpop_key_generation_rs256():
    key = generate_dpop_key("RS256")
    assert key.alg == "RS256"
    assert key.jwk["kty"] == "RSA" and "n" in key.jwk and "e" in key.jwk


def test_dpop_key_generation_rejects_unknown_alg():
    with pytest.raises(DPoPError):
        generate_dpop_key("HS256")


def test_dpop_proof_shape_es256():
    key = generate_dpop_key("ES256")
    proof = build_dpop_proof(
        key=key, htm="POST", htu="https://idp.example.com/token"
    )
    h_b64, p_b64, s_b64 = proof.split(".")
    header = json.loads(_b64u_pad(h_b64))
    claims = json.loads(_b64u_pad(p_b64))
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert header["jwk"]["kty"] == "EC"
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://idp.example.com/token"
    assert "iat" in claims and "jti" in claims
    # ES256 signature is 64 bytes (r||s).
    sig = _b64u_pad(s_b64)
    assert len(sig) == 64


def test_dpop_proof_ath_claim_when_bound():
    key = generate_dpop_key("ES256")
    at = "access-token-value"
    proof = build_dpop_proof(
        key=key, htm="GET", htu="https://api.example.com/me", access_token=at
    )
    _h, p_b64, _s = proof.split(".")
    claims = json.loads(_b64u_pad(p_b64))
    expected = base64.urlsafe_b64encode(hashlib.sha256(at.encode()).digest()).rstrip(b"=").decode()
    assert claims["ath"] == expected


def test_dpop_proof_htm_is_uppercased():
    key = generate_dpop_key("ES256")
    proof = build_dpop_proof(key=key, htm="post", htu="https://x.test/")
    _h, p_b64, _s = proof.split(".")
    claims = json.loads(_b64u_pad(p_b64))
    assert claims["htm"] == "POST"


# ---------- dpop check ----------


async def _ctx(caps: CapabilitiesReport) -> Context:
    return Context(
        tenant_id="t",
        discovery=DOC,
        capabilities=caps,
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
    )


async def test_dpop_check_dpop_and_mtls_together():
    caps = CapabilitiesReport(
        oidc=OIDCCapabilities(present=True, dpop_supported=True, mtls_bound_tokens=True)
    )
    ctx = await _ctx(caps)
    findings = await DPoPCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "dpop.advertised_with_mtls_binding" in ids
    assert "dpop.exercise_against_protected_resource" in ids


async def test_dpop_check_dpop_only_emits_exercise_pointer():
    caps = CapabilitiesReport(oidc=OIDCCapabilities(present=True, dpop_supported=True))
    ctx = await _ctx(caps)
    findings = await DPoPCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "dpop.exercise_against_protected_resource" in ids
    assert "dpop.advertised_with_mtls_binding" not in ids


async def test_dpop_check_no_dpop_no_findings():
    caps = CapabilitiesReport(oidc=OIDCCapabilities(present=True))
    ctx = await _ctx(caps)
    findings = await DPoPCheck().run(ctx)
    assert findings == []


# ---------- mTLS wiring ----------


async def test_oauth_client_stores_mtls_cert_tuple(tmp_path):
    cert_path = tmp_path / "c.pem"
    key_path = tmp_path / "c.key"
    cert_path.write_text("dummy")
    key_path.write_text("dummy")

    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            client_secret="s",
            redirect_uri="https://app.example.test/cb",
            http=http,
            mtls_cert=str(cert_path),
            mtls_key=str(key_path),
        )
        assert client.mtls_cert == (str(cert_path), str(key_path))


async def test_oauth_client_no_mtls_when_not_configured():
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            redirect_uri="https://app.example.test/cb",
            http=http,
        )
    assert client.mtls_cert is None


async def test_oauth_client_builds_client_with_cert_when_not_externally_supplied(tmp_path):
    """OAuthClient, when given cert+key paths and no external httpx client,
    must load them into an SSLContext on a self-owned client."""
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID as _NameOID

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(_NameOID.COMMON_NAME, "oauthive-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=30))
        .sign(key, _hashes.SHA256())
    )
    cert_path = tmp_path / "c.pem"
    key_path = tmp_path / "c.key"
    cert_path.write_bytes(cert.public_bytes(_serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=_serialization.Encoding.PEM,
            format=_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_serialization.NoEncryption(),
        )
    )

    client = OAuthClient(
        discovery=DOC,
        client_id="c",
        redirect_uri="https://app.example.test/cb",
        mtls_cert=str(cert_path),
        mtls_key=str(key_path),
    )
    try:
        assert client.mtls_cert == (str(cert_path), str(key_path))
        assert client._own_http is True
    finally:
        await client.aclose()


# ---------- runner mTLS skip ----------


class _MTLSCheck:
    id = "needs_mtls"
    name = "needs_mtls"
    parallel_safe = False
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc", "mtls"})

    async def run(self, ctx):  # pragma: no cover - never reached in test
        return []


async def test_runner_skips_mtls_without_cert(monkeypatch):
    caps = CapabilitiesReport(
        oidc=OIDCCapabilities(present=True, mtls_bound_tokens=True)
    )
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [_MTLSCheck()])
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC, client_id="c", redirect_uri="https://app.example.test/cb", http=http
        )
        ctx = Context(
            tenant_id="t",
            discovery=DOC,
            capabilities=caps,
            http=http,
            log=structlog.get_logger(),
            client=client,
        )
        report = await run(ctx, RunnerConfig(tenant_id="t", enabled=["all"], disabled=[]))
    rec = next(c for c in report.checks if c.id == "needs_mtls")
    assert rec.status == "skipped"
    assert "mtls" in rec.skip_reason.lower()


async def test_runner_runs_mtls_check_when_cert_present(monkeypatch, tmp_path):
    cert = tmp_path / "c.pem"
    key = tmp_path / "c.key"
    cert.write_text("x"); key.write_text("y")

    class _Ran(_MTLSCheck):
        async def run(self, ctx):
            self.ran = True
            return []

    instance = _Ran()
    instance.ran = False
    caps = CapabilitiesReport(
        oidc=OIDCCapabilities(present=True, mtls_bound_tokens=True)
    )
    monkeypatch.setattr("oauthive.runner._discover_checks", lambda: [instance])
    async with httpx.AsyncClient() as http:
        client = OAuthClient(
            discovery=DOC,
            client_id="c",
            redirect_uri="https://app.example.test/cb",
            http=http,
            mtls_cert=str(cert),
            mtls_key=str(key),
        )
        ctx = Context(
            tenant_id="t",
            discovery=DOC,
            capabilities=caps,
            http=http,
            log=structlog.get_logger(),
            client=client,
        )
        await run(ctx, RunnerConfig(tenant_id="t", enabled=["all"], disabled=[]))
    assert instance.ran is True


# ---------- playwright driver ----------


def test_playwright_driver_constructible_and_respects_totp_field():
    # Skip if the optional extra isn't installed.
    pytest.importorskip("playwright")
    from oauthive.browser.playwright_driver import PlaywrightDriver

    d = PlaywrightDriver(
        username="u", password="p", totp_secret="JBSWY3DPEHPK3PXP", headless=True
    )
    assert d.username == "u"
    assert d.totp_secret == "JBSWY3DPEHPK3PXP"


# ---------- version bump ----------


def test_version_is_0_1_0():
    assert oauthive.__version__ == "0.1.0"
