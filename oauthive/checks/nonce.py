"""OIDC nonce enforcement.

OpenID Connect Core 1.0 sec 3.1.2.1: nonce is OPTIONAL for the code flow and
REQUIRED for the implicit and hybrid flows. Sec 3.2.2.9 / 3.3.2.11: the ID
token MUST contain the nonce value when the request included one, and the RP
MUST validate it.

What we can observe externally without a live token exchange:
  - If the IdP advertises response_type='id_token' or 'code id_token' (hybrid)
    support, does it still issue a successful authorization response when
    the client omits nonce? Spec says it MUST NOT.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class NonceCheck:
    id = "nonce"
    name = "OIDC nonce enforcement"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            return []

        findings: list[Finding] = []
        supported_rt = ctx.capabilities.oidc.supported_response_types
        # Find a response_type that triggers an ID token directly from /authorize.
        id_token_rt = None
        for candidate in ("id_token", "id_token token", "code id_token", "code id_token token"):
            if candidate in supported_rt:
                id_token_rt = candidate
                break
        if id_token_rt is None:
            return []  # nothing to probe without id_token at /authorize

        # Build a request with response_type that yields id_token but NO nonce.
        params = {
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "response_type": id_token_rt,
            "scope": "openid",
            "state": "oauthive-nonce-check",
        }
        sep = "&" if "?" in str(client.discovery.authorization_endpoint) else "?"
        url = f"{client.discovery.authorization_endpoint}{sep}{urlencode(params)}"
        resp = await client._http.get(url, follow_redirects=False)

        loc = resp.headers.get("location") or ""
        if not loc or resp.status_code not in (301, 302, 303, 307):
            return findings

        parsed = urlparse(loc)
        if parsed.hostname != urlparse(client.redirect_uri).hostname:
            return findings

        # id_token appears in the fragment for implicit/hybrid.
        merged = {**parse_qs(parsed.query), **parse_qs(parsed.fragment)}
        if "id_token" in merged or "code" in merged:
            # Distinguish error redirects (they include error=...).
            if "error" in merged:
                return findings
            findings.append(
                Finding(
                    id="nonce.missing_accepted_for_implicit_or_hybrid",
                    severity="high",
                    confidence="high",
                    title=f"response_type={id_token_rt!r} accepted without nonce",
                    description=(
                        "The authorization endpoint accepted a request that asks "
                        "for an ID token directly and omitted the nonce parameter. "
                        "OpenID Connect Core sec 3.1.2.1 and 3.2.2.11 say nonce is "
                        "REQUIRED for implicit and hybrid flows; the server MUST "
                        "reject. Without nonce binding an attacker who captures an "
                        "ID token can replay it at a victim's browser."
                    ),
                    spec_ref="OpenID Connect Core 1.0 sec 3.1.2.1 and 3.2.2.11 and 3.3.2.11",
                    poc_url=loc,
                    remediation=(
                        "Require nonce for any response_type that delivers an "
                        "id_token from /authorize. If possible, disable implicit "
                        "and hybrid flows entirely on this client and migrate to "
                        "the code flow with PKCE."
                    ),
                    evidence={
                        "response_type": id_token_rt,
                        "callback_keys": sorted(merged.keys()),
                    },
                )
            )
        return findings
