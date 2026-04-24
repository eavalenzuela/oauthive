"""SAML 2.0 EntityDescriptor parser.

Parses both IdP metadata (IDPSSODescriptor) and SP metadata
(SPSSODescriptor). Surfaces endpoint-by-binding, KeyDescriptor certs split
by signing / encryption use, NameID formats, whether the entity wants
AuthnRequests or Assertions signed, and whether the metadata document
itself carries a top-level <ds:Signature>.

Parsing uses lxml; untrusted XML is pre-parsed via defusedxml to block DTDs
and entity attacks. The malicious path that *produces* such XML lives in
oauthive/saml/forge.py.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import defusedxml.ElementTree as DET
from lxml import etree

SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

NAMESPACES = {"md": SAML_METADATA_NS, "ds": DS_NS, "saml": SAML_ASSERTION_NS}


class SAMLMetadataError(RuntimeError):
    pass


@dataclass
class SingleSignOnService:
    binding: str
    location: str


@dataclass
class KeyDescriptor:
    use: str  # 'signing', 'encryption', or '' (both)
    x509_pem: str  # PEM-formatted cert


@dataclass
class EntityDescriptor:
    entity_id: str
    role: str  # 'idp', 'sp', or 'unknown'
    sso_services: list[SingleSignOnService] = field(default_factory=list)
    slo_services: list[SingleSignOnService] = field(default_factory=list)
    acs_services: list[SingleSignOnService] = field(default_factory=list)
    name_id_formats: list[str] = field(default_factory=list)
    key_descriptors: list[KeyDescriptor] = field(default_factory=list)
    want_authn_requests_signed: bool | None = None
    want_assertions_signed: bool | None = None
    metadata_signed: bool = False
    raw_xml: bytes = b""

    def sso_bindings(self) -> list[str]:
        return sorted({s.binding for s in self.sso_services})

    def slo_bindings(self) -> list[str]:
        return sorted({s.binding for s in self.slo_services})

    def signing_certs(self) -> list[str]:
        return [k.x509_pem for k in self.key_descriptors if k.use in ("signing", "")]

    def encryption_certs(self) -> list[str]:
        return [k.x509_pem for k in self.key_descriptors if k.use in ("encryption", "")]


def parse_metadata(source: bytes | str) -> EntityDescriptor:
    """Parse an EntityDescriptor. `source` may be bytes (XML) or a str path."""
    if isinstance(source, str):
        with open(source, "rb") as f:
            xml = f.read()
    else:
        xml = source

    # defusedxml check first: refuses DTDs, entities.
    try:
        DET.fromstring(xml)
    except Exception as e:  # noqa: BLE001
        raise SAMLMetadataError(f"metadata XML failed defusedxml parse: {e}") from e

    try:
        root = etree.fromstring(xml)
    except etree.XMLSyntaxError as e:
        raise SAMLMetadataError(f"metadata XML is malformed: {e}") from e

    if root.tag != f"{{{SAML_METADATA_NS}}}EntityDescriptor":
        # Could be EntitiesDescriptor; M10 only handles single entities.
        raise SAMLMetadataError(
            f"root element is {root.tag!r}, expected md:EntityDescriptor"
        )

    entity_id = root.get("entityID") or ""
    if not entity_id:
        raise SAMLMetadataError("EntityDescriptor is missing entityID attribute")

    md = EntityDescriptor(entity_id=entity_id, role="unknown", raw_xml=xml)

    # Detect top-level signature on the metadata itself.
    md.metadata_signed = (
        root.find("./ds:Signature", NAMESPACES) is not None
    )

    idp_role = root.find("./md:IDPSSODescriptor", NAMESPACES)
    sp_role = root.find("./md:SPSSODescriptor", NAMESPACES)
    if idp_role is not None:
        md.role = "idp"
        _populate_idp(md, idp_role)
    if sp_role is not None:
        md.role = "sp" if md.role == "unknown" else md.role + "+sp"
        _populate_sp(md, sp_role)

    return md


def _populate_idp(md: EntityDescriptor, role: "etree._Element") -> None:
    want = role.get("WantAuthnRequestsSigned")
    if want is not None:
        md.want_authn_requests_signed = want.lower() == "true"

    for svc in role.findall("./md:SingleSignOnService", NAMESPACES):
        binding = svc.get("Binding")
        location = svc.get("Location")
        if binding and location:
            md.sso_services.append(SingleSignOnService(binding=binding, location=location))
    for svc in role.findall("./md:SingleLogoutService", NAMESPACES):
        binding = svc.get("Binding")
        location = svc.get("Location")
        if binding and location:
            md.slo_services.append(SingleSignOnService(binding=binding, location=location))

    for fmt in role.findall("./md:NameIDFormat", NAMESPACES):
        if fmt.text:
            md.name_id_formats.append(fmt.text.strip())

    _populate_keys(md, role)


def _populate_sp(md: EntityDescriptor, role: "etree._Element") -> None:
    want_signed = role.get("WantAssertionsSigned")
    if want_signed is not None:
        md.want_assertions_signed = want_signed.lower() == "true"

    for svc in role.findall("./md:AssertionConsumerService", NAMESPACES):
        binding = svc.get("Binding")
        location = svc.get("Location")
        if binding and location:
            md.acs_services.append(SingleSignOnService(binding=binding, location=location))

    for svc in role.findall("./md:SingleLogoutService", NAMESPACES):
        binding = svc.get("Binding")
        location = svc.get("Location")
        if binding and location:
            md.slo_services.append(SingleSignOnService(binding=binding, location=location))

    for fmt in role.findall("./md:NameIDFormat", NAMESPACES):
        if fmt.text:
            md.name_id_formats.append(fmt.text.strip())

    _populate_keys(md, role)


def _populate_keys(md: EntityDescriptor, role: "etree._Element") -> None:
    for kd in role.findall("./md:KeyDescriptor", NAMESPACES):
        use = (kd.get("use") or "").lower().strip()  # 'signing' | 'encryption' | ''
        cert_el = kd.find(".//ds:X509Certificate", NAMESPACES)
        if cert_el is None or not cert_el.text:
            continue
        b64 = "".join(cert_el.text.split())
        pem = _to_pem(b64)
        md.key_descriptors.append(KeyDescriptor(use=use, x509_pem=pem))


def _to_pem(b64: str) -> str:
    chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(chunks)
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
