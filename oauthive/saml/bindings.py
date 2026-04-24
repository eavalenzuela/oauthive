"""SAML protocol bindings.

Covers encode for HTTP-Redirect and HTTP-POST. HTTP-Artifact requires a
back-channel resolve and is deferred until a check actually needs it.

This is the honest encoder side. The corresponding 'malicious' encoding
tricks (oversized RelayState, signature stripping at the binding layer,
etc.) live in forge.py / the SAML checks.
"""

from __future__ import annotations

import base64
import urllib.parse
import zlib

BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


def encode_http_redirect(
    xml: bytes,
    *,
    endpoint: str,
    relay_state: str | None = None,
    sig_alg: str | None = None,
    signature_b64: str | None = None,
    param: str = "SAMLRequest",
) -> str:
    """DEFLATE + base64 + urlencode, per SAML 2.0 Bindings sec 3.4.

    SigAlg / Signature are appended when provided; the caller signs the
    exact pre-encode byte sequence that matches the built query.
    """
    compressed = _deflate(xml)
    encoded = base64.b64encode(compressed).decode()
    parts = [(param, encoded)]
    if relay_state is not None:
        parts.append(("RelayState", relay_state))
    if sig_alg:
        parts.append(("SigAlg", sig_alg))
    if signature_b64 is not None:
        parts.append(("Signature", signature_b64))
    query = urllib.parse.urlencode(parts, quote_via=urllib.parse.quote)
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{query}"


def encode_http_post(
    xml: bytes, *, endpoint: str, relay_state: str | None = None, param: str = "SAMLRequest"
) -> str:
    """Return an HTML page that auto-submits the request to endpoint.

    Per SAML 2.0 Bindings sec 3.5: the SAML message is the base64 of the
    raw XML (no compression), embedded as a form field.
    """
    b64 = base64.b64encode(xml).decode()
    rs_field = (
        f'<input type="hidden" name="RelayState" value="{relay_state}" />'
        if relay_state is not None
        else ""
    )
    return f"""<!doctype html>
<html><body onload="document.forms[0].submit()">
<form action="{endpoint}" method="post">
  <input type="hidden" name="{param}" value="{b64}" />
  {rs_field}
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>"""


def _deflate(data: bytes) -> bytes:
    # raw DEFLATE (wbits=-15) as required by SAML Bindings sec 3.4.4.1.
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def decode_deflate_b64(b64: str) -> bytes:
    """Inverse of the HTTP-Redirect body encoding."""
    raw = base64.b64decode(b64)
    return zlib.decompress(raw, wbits=-15)
