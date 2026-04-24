"""state (CSRF-defense) posture.

RFC 6749 sec 4.1.1 and OAuth 2.0 Security BCP sec 4.7: clients that do not
send state cannot bind a callback to the originating session, enabling
login-CSRF. OAuth 2.1 mandates either state or PKCE for this purpose.

This check observes the authorization endpoint's behavior when the client
omits state entirely. IdPs cannot compensate for a missing state on the
client side, but a sane IdP will either:
  - Refuse to proceed (documented rare).
  - Warn in its error / consent UI (cannot be observed externally).
  - Or at minimum support an extension like ``iss`` in the callback
    (draft-ietf-oauth-iss-auth-resp) so the client can defend itself.

Finding granularity:
  - state.missing_accepted : the IdP issues a code to the registered
    redirect_uri with no state param at all; the operator's client is relying
    on discipline alone for CSRF defense. Informational -- the defect is
    client-side, but many IdPs tighten this at the /authorize step.
  - state.iss_not_returned : the IdP advertises OIDC but its callback does
    not include an ``iss`` parameter, preventing the client from
    distinguishing a response from a mix-up attacker's IdP.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class StateCheck:
    id = "state"
    name = "state / CSRF binding"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            return []

        findings: list[Finding] = []

        # Build an authorization request without state. We can't use
        # probe_authorization because AuthorizationRequest auto-generates a
        # state; call the lower-level helper instead.
        from ..client import AuthorizationRequest, send_authorization_request

        # Construct params manually to drop state.
        import secrets

        params = {
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "nonce": secrets.token_urlsafe(16),
        }
        from urllib.parse import urlencode

        url = (
            f"{client.discovery.authorization_endpoint}"
            f"{'&' if '?' in str(client.discovery.authorization_endpoint) else '?'}"
            f"{urlencode(params)}"
        )
        resp = await client._http.get(url, follow_redirects=False)
        loc = resp.headers.get("location") or ""
        loc_host = urlparse(loc).hostname if loc else None
        requested_host = urlparse(client.redirect_uri).hostname

        if loc and loc_host == requested_host and resp.status_code in (301, 302, 303, 307):
            q = parse_qs(urlparse(loc).query)
            if "code" in q:
                findings.append(
                    Finding(
                        id="state.missing_accepted",
                        severity="medium",
                        confidence="medium",
                        title="Authorization flow completes with no state parameter",
                        description=(
                            "The authorization endpoint issued a code to the "
                            "registered redirect_uri when the client did not send "
                            "a state parameter. Clients that omit state cannot "
                            "bind the callback to the session that started the "
                            "flow; login-CSRF is possible. Sane IdPs reject or "
                            "warn at /authorize; permissive IdPs leave CSRF "
                            "defense entirely to the RP."
                        ),
                        spec_ref="RFC 6749 sec 4.1.1; OAuth 2.0 Security BCP sec 4.7; OAuth 2.1 sec 4.1.2.1",
                        poc_url=loc,
                        remediation=(
                            "The primary fix is client-side: always send a "
                            "per-session unguessable state value and verify it on "
                            "callback. If the IdP offers a 'require state' toggle "
                            "on this client, enable it so the IdP rejects "
                            "state-less requests."
                        ),
                        evidence={
                            "status_code": resp.status_code,
                            "location": loc,
                        },
                    )
                )

            # iss-in-response check (draft-ietf-oauth-iss-auth-resp). Only
            # meaningful when we reached the callback.
            if "iss" not in q:
                findings.append(
                    Finding(
                        id="state.iss_not_returned",
                        severity="low",
                        confidence="medium",
                        title="Authorization response does not include an 'iss' parameter",
                        description=(
                            "draft-ietf-oauth-iss-auth-resp (now RFC 9207) "
                            "recommends IdPs include the issuer identifier in "
                            "successful authorization responses so clients that "
                            "talk to multiple IdPs can detect mix-up attacks. "
                            "This IdP did not."
                        ),
                        spec_ref="RFC 9207",
                        poc_url=loc,
                        remediation=(
                            "Enable RFC 9207 support ('iss' in the authorization "
                            "response) if the IdP offers it. Clients facing "
                            "multiple IdPs should require it."
                        ),
                        evidence={"callback_params": sorted(q.keys())},
                    )
                )

        return findings
