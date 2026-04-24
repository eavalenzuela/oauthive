"""Intentionally-vulnerable SAML Service Provider for oauthive smoke tests.

DO NOT deploy this anywhere. It exists to validate that oauthive's forge
primitives produce payloads a broken SP will accept.

Vulnerabilities present (by design):
  - no signature verification
  - no audience restriction enforcement
  - no Recipient / InResponseTo binding
  - NameID extracted via textContent-like path so comment injection works
  - no NotBefore / NotOnOrAfter enforcement

The healthcheck shape matches what oauthive.fixture expects so 'fixture up'
can wait on readiness.
"""

import base64

from lxml import etree
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
NS = {"samlp": SAMLP_NS, "saml": SAML_NS}


def _naive_nameid(root: "etree._Element") -> str:
    """Vulnerable textContent-style extraction: concatenates direct text,
    stops at the first comment. Mirrors the pre-CVE-2018-0489 behavior of
    several SAML libraries."""
    nameids = root.findall(".//{%s}NameID" % SAML_NS)
    if not nameids:
        return ""
    ni = nameids[0]
    # .text only captures text before the first child node; any comment or
    # element sibling is ignored. That's exactly the vulnerable path.
    return (ni.text or "").strip()


async def home(_: Request) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><h1>oauthive vulnerable SP</h1>"
        "<p>POST SAMLResponse to /acs</p>"
    )


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "UP"})


async def acs(request: Request) -> HTMLResponse:
    form = await request.form()
    saml_b64 = form.get("SAMLResponse")
    if saml_b64 is None:
        return HTMLResponse("missing SAMLResponse", status_code=400)
    try:
        xml = base64.b64decode(str(saml_b64))
        root = etree.fromstring(xml)
    except Exception as e:
        return HTMLResponse(f"bad xml: {e}", status_code=400)
    # Vulnerable: we do none of the checks a real SP should do.
    nameid = _naive_nameid(root)
    return HTMLResponse(
        f"<h1>logged in as <code>{nameid}</code></h1>"
        "<p>(vulnerable SP - no validation performed)</p>"
    )


app = Starlette(
    routes=[
        Route("/", home),
        Route("/health", health),
        Route("/acs", acs, methods=["POST"]),
    ]
)
