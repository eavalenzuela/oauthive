"""SAML 2.0 support.

- metadata : parse EntityDescriptor (IdP or SP role)
- sp       : honest SP -- build AuthnRequest, parse Response
- bindings : encode requests for HTTP-Redirect / HTTP-POST
- forge    : malicious Response / Assertion construction (M11+)
- canon    : exclusive C14N helpers
"""

from __future__ import annotations

from .metadata import (
    EntityDescriptor,
    KeyDescriptor,
    SAMLMetadataError,
    SingleSignOnService,
    parse_metadata,
)

__all__ = [
    "EntityDescriptor",
    "KeyDescriptor",
    "SAMLMetadataError",
    "SingleSignOnService",
    "parse_metadata",
]

NAMESPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}

BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
