import base64

import pytest
from lxml import etree

from oauthive.saml.bindings import (
    BINDING_POST,
    decode_deflate_b64,
    encode_http_post,
    encode_http_redirect,
)
from oauthive.saml.sp import (
    AuthnRequestParams,
    SAMLResponseError,
    build_authn_request,
    parse_response,
)


# ---------- AuthnRequest ----------


def test_build_authn_request_structure():
    params = AuthnRequestParams(
        sp_entity_id="https://sp.example.test/saml/sp",
        acs_url="https://sp.example.test/acs",
        destination="https://idp.example.test/saml/sso",
        protocol_binding=BINDING_POST,
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        force_authn=True,
    )
    xml, rid = build_authn_request(params)
    assert rid.startswith("_")
    root = etree.fromstring(xml)
    assert root.tag.endswith("AuthnRequest")
    assert root.get("ID") == rid
    assert root.get("Destination") == params.destination
    assert root.get("AssertionConsumerServiceURL") == params.acs_url
    assert root.get("ForceAuthn") == "true"
    # Issuer + NameIDPolicy present
    ns = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    }
    issuer = root.find("./saml:Issuer", ns)
    assert issuer is not None
    assert issuer.text == params.sp_entity_id
    policy = root.find("./samlp:NameIDPolicy", ns)
    assert policy is not None
    assert policy.get("Format") == params.name_id_format


def test_build_authn_request_custom_id():
    params = AuthnRequestParams(
        sp_entity_id="x",
        acs_url="https://sp.example.test/acs",
        destination="https://idp.example.test/sso",
    )
    xml, rid = build_authn_request(params, request_id="_fixed-abc")
    assert rid == "_fixed-abc"
    assert b'ID="_fixed-abc"' in xml


# ---------- bindings ----------


def test_http_redirect_encoding_roundtrip():
    xml, _rid = build_authn_request(
        AuthnRequestParams(
            sp_entity_id="x",
            acs_url="https://sp.example.test/acs",
            destination="https://idp.example.test/sso",
        )
    )
    url = encode_http_redirect(
        xml, endpoint="https://idp.example.test/sso", relay_state="rs-value"
    )
    assert url.startswith("https://idp.example.test/sso?")
    import urllib.parse

    q = dict(urllib.parse.parse_qsl(url.split("?", 1)[1]))
    assert q["RelayState"] == "rs-value"
    assert q["SAMLRequest"]
    roundtrip = decode_deflate_b64(q["SAMLRequest"])
    assert roundtrip == xml


def test_http_redirect_signature_fields():
    xml = b"<x/>"
    url = encode_http_redirect(
        xml,
        endpoint="https://idp.example.test/sso",
        sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        signature_b64="ZmFrZS1zaWc=",
    )
    import urllib.parse

    q = dict(urllib.parse.parse_qsl(url.split("?", 1)[1]))
    assert q["SigAlg"].endswith("rsa-sha256")
    assert q["Signature"] == "ZmFrZS1zaWc="


def test_http_post_produces_auto_submitting_form():
    xml = b"<x/>"
    html = encode_http_post(
        xml, endpoint="https://idp.example.test/sso", relay_state="rs"
    )
    b64 = base64.b64encode(xml).decode()
    assert b'SAMLRequest' in html.encode()
    assert b64 in html
    assert 'RelayState' in html
    assert 'document.forms[0].submit()' in html


# ---------- Response parsing ----------


RESPONSE_WITH_ASSERTION = b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp-id-1" InResponseTo="_req-1"
                IssueInstant="2025-01-01T00:00:00Z" Version="2.0"
                Destination="https://sp.example.test/acs">
  <saml:Issuer>https://idp.example.test/saml</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a-1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.test/saml</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.test</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            InResponseTo="_req-1"
            Recipient="https://sp.example.test/acs"
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


def test_parse_response_basic():
    r = parse_response(RESPONSE_WITH_ASSERTION)
    assert r.id == "_resp-id-1"
    assert r.in_response_to == "_req-1"
    assert r.issuer == "https://idp.example.test/saml"
    assert r.status_code.endswith("Success")
    assert r.signed is False
    assert len(r.assertions) == 1
    a = r.assertions[0]
    assert a.issuer == "https://idp.example.test/saml"
    assert a.subject_name_id == "alice@example.test"
    assert a.audiences == ["https://sp.example.test/saml/sp"]
    assert a.recipient == "https://sp.example.test/acs"
    assert a.in_response_to == "_req-1"
    assert a.not_on_or_after == "2025-01-01T00:10:00Z"


def test_parse_response_detects_signature():
    signed = RESPONSE_WITH_ASSERTION.replace(
        b"<samlp:Status>",
        b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><samlp:Status>',
    )
    r = parse_response(signed)
    assert r.signed is True


def test_parse_response_counts_encrypted_assertions():
    wrapped = b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_r" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>https://idp</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="ok"/></samlp:Status>
  <saml:EncryptedAssertion/>
  <saml:EncryptedAssertion/>
</samlp:Response>"""
    r = parse_response(wrapped)
    assert r.encrypted_assertions == 2
    assert r.assertions == []


def test_parse_response_rejects_wrong_root():
    with pytest.raises(SAMLResponseError, match="samlp:Response"):
        parse_response(b"<foo/>")


def test_parse_response_rejects_doctype():
    bad = b"""<!DOCTYPE samlp:Response [<!ENTITY x "y">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_r" Version="2.0" IssueInstant="x"/>"""
    with pytest.raises(SAMLResponseError):
        parse_response(bad)
