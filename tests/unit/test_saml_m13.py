"""Tests for M13: metadata extensions + saml_encryption / saml_slo / saml_metadata checks + logout forge."""

from __future__ import annotations

import datetime as dt

import httpx
import structlog
from lxml import etree

from oauthive.capabilities import CapabilitiesReport, derive_from_saml_metadata
from oauthive.checks.saml_encryption import SAMLEncryptionCheck
from oauthive.checks.saml_metadata import SAMLMetadataCheck
from oauthive.checks.saml_slo import SAMLSLOCheck
from oauthive.context import Context
from oauthive.saml.forge import build_logout_request
from oauthive.saml.metadata import parse_metadata

SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"


def _b64_cert(key_bits: int = 2048) -> str:
    """Return the base64 blob (no PEM headers) of a freshly-minted cert."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oauthive-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return "".join(line for line in pem.split("\n") if line and "CERT" not in line)


def _idp_md(
    *,
    encryption_methods: list[str] | None = None,
    enc_key_bits: int = 2048,
    slo: bool = True,
    valid_until: str | None = None,
) -> bytes:
    methods_xml = (
        "\n".join(
            f'        <md:EncryptionMethod Algorithm="{m}"/>' for m in (encryption_methods or [])
        )
    )
    slo_xml = (
        '    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://idp.example.test/slo"/>' if slo else ""
    )
    valid_until_attr = f' validUntil="{valid_until}"' if valid_until else ""
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="{MD_NS}"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.test/saml"{valid_until_attr}>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{_b64_cert(2048)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{_b64_cert(enc_key_bits)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
{methods_xml}
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.test/sso"/>
{slo_xml}
  </md:IDPSSODescriptor>
</md:EntityDescriptor>""".encode()


async def _ctx_from(xml: bytes, *, source_url: str | None = None) -> Context:
    md = parse_metadata(xml, source_url=source_url)
    caps = CapabilitiesReport(saml=derive_from_saml_metadata(md))
    return Context(
        tenant_id="t",
        discovery=None,
        capabilities=caps,
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
        saml_metadata=md,
    )


# ---------- metadata parser extensions ----------


def test_valid_until_parsing():
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    md = parse_metadata(_idp_md(valid_until=future))
    assert md.valid_until is not None
    assert md.valid_until.tzinfo is not None


def test_valid_until_malformed_is_ignored():
    md = parse_metadata(_idp_md(valid_until="not-a-date"))
    assert md.valid_until is None


def test_encryption_methods_extracted():
    md = parse_metadata(
        _idp_md(
            encryption_methods=[
                "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            ]
        )
    )
    algs = md.encryption_methods()
    assert "http://www.w3.org/2001/04/xmlenc#rsa-1_5" in algs
    assert "http://www.w3.org/2001/04/xmlenc#aes256-cbc" in algs


def test_source_url_threading():
    md = parse_metadata(_idp_md(), source_url="http://idp.example.test/md")
    assert md.source_url == "http://idp.example.test/md"


# ---------- build_logout_request ----------


def test_build_logout_request_shape():
    xml = build_logout_request(
        issuer="https://sp.example.test/saml/sp",
        destination="https://idp.example.test/slo",
        name_id="alice@example.test",
        session_index="idx-1",
        request_id="_logout-1",
    )
    root = etree.fromstring(xml)
    assert root.tag == f"{{{SAMLP_NS}}}LogoutRequest"
    assert root.get("ID") == "_logout-1"
    assert root.find(f"./{{{SAML_NS}}}Issuer").text == "https://sp.example.test/saml/sp"
    nameid = root.find(f"./{{{SAML_NS}}}NameID")
    assert nameid.text == "alice@example.test"
    assert root.find(f"./{{{SAMLP_NS}}}SessionIndex").text == "idx-1"


def test_build_logout_request_without_session_index():
    xml = build_logout_request(
        issuer="x", destination="y", name_id="z",
    )
    root = etree.fromstring(xml)
    assert root.find(f"./{{{SAMLP_NS}}}SessionIndex") is None


# ---------- saml_encryption ----------


async def test_saml_encryption_rsa_1_5_flag():
    xml = _idp_md(encryption_methods=["http://www.w3.org/2001/04/xmlenc#rsa-1_5"])
    ctx = await _ctx_from(xml)
    findings = await SAMLEncryptionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_encryption.rsa_1_5_wrap_advertised" in ids


async def test_saml_encryption_cbc_flag():
    xml = _idp_md(encryption_methods=["http://www.w3.org/2001/04/xmlenc#aes128-cbc"])
    ctx = await _ctx_from(xml)
    findings = await SAMLEncryptionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_encryption.cbc_mode_advertised" in ids


async def test_saml_encryption_weak_key_flag():
    xml = _idp_md(enc_key_bits=1024)
    ctx = await _ctx_from(xml)
    findings = await SAMLEncryptionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_encryption.encryption_key_weak[0]" in ids


async def test_saml_encryption_always_surfaces_exercise_pointer():
    xml = _idp_md()  # no weak bits, no weak algs
    ctx = await _ctx_from(xml)
    findings = await SAMLEncryptionCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_encryption.exercise_against_sp" in ids


# ---------- saml_slo ----------


async def test_saml_slo_no_single_logout_service():
    xml = _idp_md(slo=False)
    ctx = await _ctx_from(xml)
    findings = await SAMLSLOCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_slo.no_single_logout_service" in ids
    assert "saml_slo.exercise_unsigned_logout" not in ids


async def test_saml_slo_exercise_pointer_when_endpoint_present():
    xml = _idp_md(slo=True)
    ctx = await _ctx_from(xml)
    findings = await SAMLSLOCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_slo.exercise_unsigned_logout" in ids
    # Reproducer command referenced
    f = next(f for f in findings if f.id == "saml_slo.exercise_unsigned_logout")
    assert "build_logout_request" in f.description


# ---------- saml_metadata ----------


async def test_saml_metadata_fetched_over_http():
    xml = _idp_md()
    ctx = await _ctx_from(xml, source_url="http://idp.example.test/md")
    findings = await SAMLMetadataCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_metadata.fetched_over_http" in ids


async def test_saml_metadata_fetched_over_https_no_finding():
    xml = _idp_md(
        valid_until=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    ctx = await _ctx_from(xml, source_url="https://idp.example.test/md")
    findings = await SAMLMetadataCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_metadata.fetched_over_http" not in ids
    assert "saml_metadata.valid_until_absent" not in ids


async def test_saml_metadata_valid_until_expired():
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    xml = _idp_md(valid_until=past)
    ctx = await _ctx_from(xml)
    findings = await SAMLMetadataCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_metadata.valid_until_expired" in ids


async def test_saml_metadata_valid_until_absent():
    xml = _idp_md()
    ctx = await _ctx_from(xml)
    findings = await SAMLMetadataCheck().run(ctx)
    ids = {f.id for f in findings}
    assert "saml_metadata.valid_until_absent" in ids


async def test_saml_metadata_skips_without_metadata():
    ctx = Context(
        tenant_id="t",
        discovery=None,
        capabilities=CapabilitiesReport(),
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
        saml_metadata=None,
    )
    assert await SAMLMetadataCheck().run(ctx) == []
    assert await SAMLEncryptionCheck().run(ctx) == []
    assert await SAMLSLOCheck().run(ctx) == []
