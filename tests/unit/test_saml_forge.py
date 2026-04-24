import pytest
from lxml import etree

from oauthive.saml.forge import (
    SAMLForgeError,
    downgrade_sig_alg,
    inject_nameid_comment,
    minimal_response_template,
    strip_signature,
    swap_key_info,
    xsw1,
)

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
  <ds:Signature>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_resp-1">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>xxx</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>ORIGINAL-CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
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
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            InResponseTo="_req-1" Recipient="https://sp.example.test/acs"
            NotOnOrAfter="2025-01-01T00:10:00Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2025-01-01T00:10:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.test/saml/sp</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"""


def _parse(xml: bytes):
    return etree.fromstring(xml)


def test_strip_signature_removes_every_signature():
    out = strip_signature(SIGNED_RESPONSE)
    root = _parse(out)
    assert root.xpath(".//ds:Signature", namespaces=NS) == []
    # But the assertion structure is intact.
    assert root.xpath(".//saml:Assertion/saml:Subject/saml:NameID", namespaces=NS)[0].text == "alice@example.test"


def test_downgrade_sig_alg_rewrites_methods():
    out = downgrade_sig_alg(SIGNED_RESPONSE)
    root = _parse(out)
    methods = root.xpath(".//ds:SignatureMethod/@Algorithm", namespaces=NS)
    digests = root.xpath(".//ds:DigestMethod/@Algorithm", namespaces=NS)
    assert all(a.endswith("rsa-sha1") for a in methods)
    assert all(a.endswith("#sha1") for a in digests)


def test_swap_key_info_replaces_certs():
    out = swap_key_info(SIGNED_RESPONSE, "ATTACKER-CERT-B64")
    root = _parse(out)
    certs = [c.text for c in root.xpath(".//ds:KeyInfo//ds:X509Certificate", namespaces=NS)]
    assert certs and all(c == "ATTACKER-CERT-B64" for c in certs)


def test_swap_key_info_errors_when_no_keyinfo():
    # Response without KeyInfo
    bare = strip_signature(SIGNED_RESPONSE)
    with pytest.raises(SAMLForgeError):
        swap_key_info(bare, "x")


def test_inject_nameid_comment_produces_split_textnodes():
    out = inject_nameid_comment(SIGNED_RESPONSE, victim="admin@victim.test")
    root = _parse(out)
    nameid = root.xpath(".//saml:NameID", namespaces=NS)[0]
    # text_nodes and comment are both present.
    assert nameid.text == "admin@victim.test"
    children = list(nameid)
    assert len(children) == 1
    assert children[0].tag is etree.Comment
    assert children[0].tail == ".attacker.test"


def test_xsw1_produces_two_assertions_with_signed_clone_in_extensions():
    out = xsw1(SIGNED_RESPONSE, evil_subject_name_id="admin@victim.test")
    root = _parse(out)
    direct = root.xpath("./saml:Assertion", namespaces=NS)
    assert len(direct) == 1
    evil_nameid = direct[0].xpath(".//saml:NameID", namespaces=NS)[0].text
    assert evil_nameid == "admin@victim.test"
    # Evil copy has its Signature removed; the original signature lives
    # inside the parasitic Extensions element.
    assert direct[0].xpath(".//ds:Signature", namespaces=NS) == []
    clones = root.xpath("./samlp:Extensions/saml:Assertion", namespaces=NS)
    assert len(clones) == 1
    assert clones[0].xpath(".//ds:Signature", namespaces=NS)


def test_minimal_response_template_shape():
    out = minimal_response_template(
        issuer="https://idp.example.test/saml",
        audience="https://sp.example.test/sp",
        recipient="https://sp.example.test/acs",
        in_response_to="_req-1",
        subject_name_id="alice@example.test",
        not_on_or_after="2025-01-01T00:10:00Z",
        not_before="2025-01-01T00:00:00Z",
    )
    root = _parse(out)
    assert root.xpath(".//saml:Audience", namespaces=NS)[0].text == "https://sp.example.test/sp"
    assert root.xpath(".//saml:NameID", namespaces=NS)[0].text == "alice@example.test"


def test_strip_signature_rejects_malformed():
    with pytest.raises(SAMLForgeError):
        strip_signature(b"<<not xml>>")
