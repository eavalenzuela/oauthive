"""Honest SAML Service Provider.

Builds AuthnRequests and parses top-level Responses. Signature verification
and assertion-claim validation live in the M11+ checks (saml_signature,
saml_assertion, etc.) so the checks can compare advertised to observed
behavior; this module stays 'does what a well-behaved SP would do'.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import defusedxml.ElementTree as DET
from lxml import etree

SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
NSMAP = {"samlp": SAMLP_NS, "saml": SAML_NS}


@dataclass
class AuthnRequestParams:
    sp_entity_id: str
    acs_url: str
    destination: str
    protocol_binding: str | None = None
    name_id_format: str | None = None
    force_authn: bool = False
    is_passive: bool = False


def _new_id() -> str:
    # SAML IDs must be NCNames; hex prefix avoids leading digits.
    return "_" + secrets.token_hex(16)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_authn_request(p: AuthnRequestParams, *, request_id: str | None = None) -> tuple[bytes, str]:
    """Return (xml_bytes, request_id). request_id is returned so the caller
    can stash it and verify the Response's InResponseTo matches."""
    rid = request_id or _new_id()
    root = etree.Element(
        f"{{{SAMLP_NS}}}AuthnRequest",
        nsmap={"samlp": SAMLP_NS, "saml": SAML_NS},
        attrib={
            "ID": rid,
            "Version": "2.0",
            "IssueInstant": _now_utc_iso(),
            "Destination": p.destination,
            "AssertionConsumerServiceURL": p.acs_url,
        },
    )
    if p.protocol_binding:
        root.set("ProtocolBinding", p.protocol_binding)
    if p.force_authn:
        root.set("ForceAuthn", "true")
    if p.is_passive:
        root.set("IsPassive", "true")

    issuer = etree.SubElement(root, f"{{{SAML_NS}}}Issuer")
    issuer.text = p.sp_entity_id

    if p.name_id_format:
        fmt = etree.SubElement(root, f"{{{SAMLP_NS}}}NameIDPolicy")
        fmt.set("Format", p.name_id_format)
        fmt.set("AllowCreate", "true")

    return etree.tostring(root, xml_declaration=False, encoding="utf-8"), rid


# ---------- Response parsing ----------


@dataclass
class ParsedAssertion:
    issuer: str | None
    subject_name_id: str | None
    audiences: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_on_or_after: str | None = None
    recipient: str | None = None
    in_response_to: str | None = None
    raw: bytes = b""


@dataclass
class ParsedResponse:
    id: str | None
    in_response_to: str | None
    issuer: str | None
    status_code: str | None
    assertions: list[ParsedAssertion] = field(default_factory=list)
    encrypted_assertions: int = 0
    signed: bool = False
    raw: bytes = b""


class SAMLResponseError(RuntimeError):
    pass


def parse_response(xml: bytes) -> ParsedResponse:
    """Shallow parse of a <samlp:Response>. Does not validate signatures."""
    try:
        DET.fromstring(xml)
    except Exception as e:  # noqa: BLE001
        raise SAMLResponseError(f"response failed defusedxml parse: {e}") from e
    try:
        root = etree.fromstring(xml)
    except etree.XMLSyntaxError as e:
        raise SAMLResponseError(f"response is malformed: {e}") from e

    if root.tag != f"{{{SAMLP_NS}}}Response":
        raise SAMLResponseError(
            f"root element is {root.tag!r}, expected samlp:Response"
        )

    issuer_el = root.find("./saml:Issuer", NSMAP)
    status_code_el = root.find("./samlp:Status/samlp:StatusCode", NSMAP)
    signature_el = root.find(
        "./{http://www.w3.org/2000/09/xmldsig#}Signature"
    )

    resp = ParsedResponse(
        id=root.get("ID"),
        in_response_to=root.get("InResponseTo"),
        issuer=(issuer_el.text.strip() if (issuer_el is not None and issuer_el.text) else None),
        status_code=(status_code_el.get("Value") if status_code_el is not None else None),
        signed=signature_el is not None,
        raw=xml,
    )

    for a in root.findall("./saml:Assertion", NSMAP):
        resp.assertions.append(_parse_assertion(a))
    resp.encrypted_assertions = len(root.findall("./saml:EncryptedAssertion", NSMAP))
    return resp


def _parse_assertion(a: "etree._Element") -> ParsedAssertion:
    issuer_el = a.find("./saml:Issuer", NSMAP)
    nameid_el = a.find("./saml:Subject/saml:NameID", NSMAP)
    subj_conf_el = a.find(
        "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NSMAP
    )
    conditions_el = a.find("./saml:Conditions", NSMAP)

    audiences: list[str] = []
    if conditions_el is not None:
        for aud_el in conditions_el.findall(
            "./saml:AudienceRestriction/saml:Audience", NSMAP
        ):
            if aud_el.text:
                audiences.append(aud_el.text.strip())

    return ParsedAssertion(
        issuer=(issuer_el.text.strip() if (issuer_el is not None and issuer_el.text) else None),
        subject_name_id=(
            nameid_el.text.strip() if (nameid_el is not None and nameid_el.text) else None
        ),
        audiences=audiences,
        not_before=(conditions_el.get("NotBefore") if conditions_el is not None else None),
        not_on_or_after=(conditions_el.get("NotOnOrAfter") if conditions_el is not None else None),
        recipient=(subj_conf_el.get("Recipient") if subj_conf_el is not None else None),
        in_response_to=(subj_conf_el.get("InResponseTo") if subj_conf_el is not None else None),
        raw=etree.tostring(a, xml_declaration=False, encoding="utf-8"),
    )


def extract_saml_response_from_form(form_data: dict[str, Any]) -> bytes:
    """Decode a base64-wrapped SAMLResponse field out of an HTTP-POST form."""
    val = form_data.get("SAMLResponse")
    if val is None:
        raise SAMLResponseError("form has no SAMLResponse field")
    return base64.b64decode(val)
