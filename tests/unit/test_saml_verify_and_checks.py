import datetime as dt

import httpx
import pytest
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oauthive.capabilities import CapabilitiesReport, derive_from_saml_metadata
from oauthive.checks.saml_assertion import SAMLAssertionCheck
from oauthive.checks.saml_idp_initiated import SAMLIdPInitiatedCheck
from oauthive.checks.saml_relaystate import SAMLRelayStateCheck
from oauthive.checks.saml_signature import SAMLSignatureCheck
from oauthive.context import Context
from oauthive.saml.metadata import parse_metadata
from oauthive.saml.verify import (
    CertInspectionError,
    inspect_cert,
    public_key_is_weak,
    signature_alg_is_weak,
)


# ---------- cert helpers to build realistic inputs ----------


def _make_cert(
    *,
    key_bits: int = 2048,
    signature_hash=hashes.SHA256(),
    days_valid: int = 365,
    offset_days: int = 0,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=offset_days)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oauthive-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .sign(key, signature_hash)
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _md_with_cert(pem_bytes: bytes, *, want_authn_requests_signed: bool = True) -> bytes:
    # Embed cert base64 inside KeyDescriptor.
    b64 = "".join(
        line for line in pem_bytes.decode().split("\n") if line and "CERT" not in line
    )
    want = "true" if want_authn_requests_signed else "false"
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.test/saml">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="{want}"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>""".encode()


# ---------- verify helpers ----------


def test_inspect_cert_rsa_happy():
    info = inspect_cert(_make_cert(key_bits=2048))
    assert info.public_key_type == "RSA"
    assert info.public_key_bits == 2048
    assert not info.is_expired
    assert signature_alg_is_weak(info) is False
    assert public_key_is_weak(info) is False


def test_public_key_is_weak_for_1024_rsa():
    info = inspect_cert(_make_cert(key_bits=1024))
    assert public_key_is_weak(info) is True


def test_signature_alg_is_weak_for_known_oid():
    # Modern cryptography refuses to produce a SHA-1 signed cert at all, which
    # is itself a policy win but means we can't build one for a test. Exercise
    # the classifier directly.
    from oauthive.saml.verify import CertInfo, signature_alg_is_weak

    info = CertInfo(
        subject="CN=x", issuer="CN=x",
        not_before=dt.datetime.now(dt.timezone.utc),
        not_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        public_key_type="RSA", public_key_bits=2048,
        signature_algorithm_oid="1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
        signature_algorithm_name="sha1WithRSAEncryption",
        is_expired=False, is_self_signed=True,
    )
    assert signature_alg_is_weak(info) is True


def test_inspect_cert_rejects_malformed():
    with pytest.raises(CertInspectionError):
        inspect_cert(b"not a pem")


def test_inspect_cert_detects_expired():
    info = inspect_cert(_make_cert(days_valid=1, offset_days=-10))
    assert info.is_expired is True


# ---------- posture checks ----------


async def _ctx_from_metadata(xml: bytes, http: httpx.AsyncClient) -> Context:
    md = parse_metadata(xml)
    caps = CapabilitiesReport(saml=derive_from_saml_metadata(md))
    return Context(
        tenant_id="t",
        discovery=None,
        capabilities=caps,
        http=http,
        log=structlog.get_logger(),
        saml_metadata=md,
    )


async def test_saml_signature_want_authn_requests_signed_false():
    xml = _md_with_cert(_make_cert(), want_authn_requests_signed=False)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_signature.want_authn_requests_signed_false" in ids


async def test_saml_signature_weak_key_flagged():
    xml = _md_with_cert(_make_cert(key_bits=1024))
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_signature.signing_key_weak[0]" in ids


async def test_saml_signature_weak_alg_flagged(monkeypatch):
    # Build a strong cert, then monkeypatch inspect_cert so the check sees it
    # as having been signed with a weak algorithm.
    from oauthive.checks import saml_signature as mod
    from oauthive.saml.verify import CertInfo

    strong = _make_cert(key_bits=2048)
    xml = _md_with_cert(strong)

    real_inspect = mod.inspect_cert

    def fake(pem):
        info = real_inspect(pem)
        return CertInfo(
            subject=info.subject, issuer=info.issuer,
            not_before=info.not_before, not_after=info.not_after,
            public_key_type=info.public_key_type, public_key_bits=info.public_key_bits,
            signature_algorithm_oid="1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
            signature_algorithm_name="sha1WithRSAEncryption",
            is_expired=info.is_expired, is_self_signed=info.is_self_signed,
        )

    monkeypatch.setattr(mod, "inspect_cert", fake)
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_signature.signing_cert_weak_sig_alg[0]" in ids


async def test_saml_signature_expired_cert_flagged():
    xml = _md_with_cert(_make_cert(days_valid=1, offset_days=-10))
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_signature.signing_cert_expired[0]" in ids


async def test_saml_signature_strong_cert_no_findings():
    xml = _md_with_cert(_make_cert(key_bits=2048))
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    assert findings == []


async def test_saml_signature_no_signing_cert():
    xml = b"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.test/saml">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLSignatureCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_signature.no_signing_cert" in ids


async def test_saml_assertion_unsigned_metadata_info():
    xml = _md_with_cert(_make_cert())
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLAssertionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_assertion.metadata_unsigned" in ids


async def test_saml_assertion_want_signed_false_on_sp():
    xml = b"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://sp.example.test/saml/sp">
  <md:SPSSODescriptor WantAssertionsSigned="false"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.test/acs"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLAssertionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_assertion.want_assertions_signed_false" in ids


async def test_saml_relaystate_info_always_fires_when_saml_present():
    xml = _md_with_cert(_make_cert())
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLRelayStateCheck().run(ctx)
    assert findings and findings[0].id == "saml_relaystate.metadata_declares_nothing"


async def test_saml_idp_initiated_info_always_fires_when_saml_present():
    xml = _md_with_cert(_make_cert())
    async with httpx.AsyncClient() as http:
        ctx = await _ctx_from_metadata(xml, http)
        findings = await SAMLIdPInitiatedCheck().run(ctx)
    assert findings and findings[0].id == "saml_idp_initiated.requires_sp_posture_check"


async def test_saml_checks_skip_without_metadata():
    async with httpx.AsyncClient() as http:
        ctx = Context(
            tenant_id="t",
            discovery=None,
            capabilities=CapabilitiesReport(),
            http=http,
            log=structlog.get_logger(),
            saml_metadata=None,
        )
        assert await SAMLSignatureCheck().run(ctx) == []
        assert await SAMLAssertionCheck().run(ctx) == []
        assert await SAMLRelayStateCheck().run(ctx) == []
        assert await SAMLIdPInitiatedCheck().run(ctx) == []
