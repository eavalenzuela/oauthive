import pytest

from oauthive.capabilities import derive_from_saml_metadata
from oauthive.saml.metadata import SAMLMetadataError, parse_metadata

IDP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.test/saml">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIBsample-signing-cert-base64==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIBsample-encryption-cert==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/saml/sso"/>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/saml/sso"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.test/saml/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

SP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://sp.example.test/saml/sp">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.test/acs"
        index="0" isDefault="true"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

SIGNED_METADATA = b"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.test/saml">
  <ds:Signature><ds:SignedInfo/><ds:SignatureValue>xx</ds:SignatureValue></ds:Signature>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def test_parse_idp_metadata_basics():
    md = parse_metadata(IDP_XML)
    assert md.entity_id == "https://idp.example.test/saml"
    assert md.role == "idp"
    assert md.want_authn_requests_signed is True
    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in md.sso_bindings()
    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in md.sso_bindings()
    assert len(md.sso_services) == 2
    assert len(md.slo_services) == 1
    assert "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" in md.name_id_formats


def test_parse_idp_splits_key_descriptors_by_use():
    md = parse_metadata(IDP_XML)
    assert len(md.signing_certs()) == 1
    assert len(md.encryption_certs()) == 1
    assert "BEGIN CERTIFICATE" in md.signing_certs()[0]


def test_parse_sp_metadata_basics():
    md = parse_metadata(SP_XML)
    assert md.entity_id == "https://sp.example.test/saml/sp"
    assert md.role == "sp"
    assert md.want_assertions_signed is True
    assert any(s.location == "https://sp.example.test/acs" for s in md.acs_services)


def test_metadata_signed_detection():
    md = parse_metadata(SIGNED_METADATA)
    assert md.metadata_signed is True

    md2 = parse_metadata(IDP_XML)
    assert md2.metadata_signed is False


def test_parse_rejects_non_entity_descriptor():
    with pytest.raises(SAMLMetadataError, match="EntityDescriptor"):
        parse_metadata(b"<foo/>")


def test_parse_rejects_missing_entity_id():
    bad = b"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>"""
    with pytest.raises(SAMLMetadataError, match="entityID"):
        parse_metadata(bad)


def test_parse_rejects_doctype():
    # defusedxml must block this.
    bad = b"""<!DOCTYPE foo [<!ENTITY x "y">]>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="x">
 <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</md:EntityDescriptor>"""
    with pytest.raises(SAMLMetadataError):
        parse_metadata(bad)


def test_derive_saml_capabilities_from_idp():
    md = parse_metadata(IDP_XML)
    caps = derive_from_saml_metadata(md)
    assert caps.present is True
    assert caps.entity_id == "https://idp.example.test/saml"
    assert caps.want_authn_requests_signed is True
    assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in caps.sso_bindings


def test_capability_tags_include_saml():
    from oauthive.capabilities import CapabilitiesReport

    md = parse_metadata(IDP_XML)
    report = CapabilitiesReport(saml=derive_from_saml_metadata(md))
    assert "saml" in report.capability_tags()
