"""RP-initiated logout posture.

OpenID Connect RP-Initiated Logout 1.0. The end_session_endpoint lets an RP
send the user to the IdP to terminate the IdP session and optionally continue
to a post_logout_redirect_uri.

What we can observe at /end_session without following the user agent:
  - The endpoint ignores id_token_hint (spec says it SHOULD be supplied so
    the IdP can pick the right session; some IdPs further require it so the
    endpoint can't be used as a CSRF trigger).
  - post_logout_redirect_uri acceptance: like redirect_uri at /authorize,
    the IdP should match exactly against the registered list. Accepting an
    attacker-controlled host is a high-severity open-redirect on the
    logout flow.

Discovery-level:
  - end_session_endpoint absent: RPs cannot reliably terminate the IdP
    session centrally; informational.
  - backchannel_logout_supported / frontchannel_logout_supported both
    absent: the IdP has no way to notify RPs that a session has ended,
    so single sign-out is effectively broken.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


class LogoutCheck:
    id = "logout"
    name = "RP-initiated logout"
    parallel_safe = False  # terminates the session it's sharing
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        if ctx.discovery is None:
            return []
        findings: list[Finding] = []

        endpoint = ctx.discovery.end_session_endpoint
        if endpoint is None:
            findings.append(
                Finding(
                    id="logout.no_end_session_endpoint",
                    severity="info",
                    confidence="high",
                    title="Discovery does not advertise end_session_endpoint",
                    description=(
                        "Without an RP-initiated logout endpoint, RPs cannot "
                        "centrally terminate the IdP session. Users logging out "
                        "of an RP leave their IdP session live, which undermines "
                        "SSO hygiene."
                    ),
                    spec_ref="OpenID Connect RP-Initiated Logout 1.0 sec 2",
                    remediation=(
                        "Enable the RP-Initiated Logout endpoint and publish it "
                        "in discovery."
                    ),
                    evidence={},
                )
            )
        else:
            findings.extend(await _probe_logout(ctx, str(endpoint)))

        if (
            not ctx.capabilities.oidc.backchannel_logout
            and not getattr(ctx.discovery, "frontchannel_logout_supported", False)
        ):
            findings.append(
                Finding(
                    id="logout.no_session_notification",
                    severity="low",
                    confidence="high",
                    title="IdP supports neither backchannel nor frontchannel logout",
                    description=(
                        "Without either notification channel, the IdP cannot "
                        "inform RPs that a user has logged out. Single sign-out "
                        "is effectively impossible."
                    ),
                    spec_ref=(
                        "OpenID Connect Back-Channel Logout 1.0 sec 4; "
                        "OpenID Connect Front-Channel Logout 1.0 sec 3"
                    ),
                    remediation=(
                        "Enable at least Back-Channel Logout; if any RPs run in "
                        "browser-only contexts, also enable Front-Channel Logout."
                    ),
                    evidence={
                        "backchannel": ctx.capabilities.oidc.backchannel_logout,
                    },
                )
            )

        return findings


async def _probe_logout(ctx: "Context", endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    client = ctx.client
    if client is None:
        return findings
    http = ctx.http

    # (1) Probe with no id_token_hint at all. Many IdPs accept this and
    # immediately redirect to post_logout_redirect_uri -- that means any
    # attacker-hosted page can CSRF the logout.
    sep = "&" if "?" in endpoint else "?"
    url = (
        f"{endpoint}{sep}"
        f"{urlencode({'post_logout_redirect_uri': client.redirect_uri})}"
    )
    resp = await http.get(url, follow_redirects=False)
    if resp.status_code in (301, 302, 303, 307):
        loc = resp.headers.get("location") or ""
        loc_host = urlparse(loc).hostname
        if loc_host == urlparse(client.redirect_uri).hostname:
            findings.append(
                Finding(
                    id="logout.no_id_token_hint_required",
                    severity="medium",
                    confidence="high",
                    title="end_session_endpoint redirects without id_token_hint",
                    description=(
                        "The logout endpoint honored a request that did not "
                        "include id_token_hint and redirected the user-agent to "
                        "the RP's post-logout URL anyway. Combined with a "
                        "permissive post_logout_redirect_uri policy, any site "
                        "can cause the user to be logged out of the IdP."
                    ),
                    spec_ref="OpenID Connect RP-Initiated Logout 1.0 sec 3; sec 2 RECOMMENDED",
                    poc_url=url,
                    remediation=(
                        "Require id_token_hint (or at least a logout-state token) "
                        "before acting on RP-initiated logout requests."
                    ),
                    evidence={"status_code": resp.status_code, "location": loc},
                )
            )

    # (2) Attacker-controlled post_logout_redirect_uri. Same approach as the
    # redirect_uri check: if the IdP redirects the user-agent to evil, that's
    # a medium-severity open redirect at best and session-scoped CSRF at
    # worst.
    evil = "https://evil.example.test/logged-out"
    params = urlencode({"post_logout_redirect_uri": evil})
    url_evil = f"{endpoint}{sep}{params}"
    resp2 = await http.get(url_evil, follow_redirects=False)
    if resp2.status_code in (301, 302, 303, 307):
        loc2 = resp2.headers.get("location") or ""
        if urlparse(loc2).hostname == "evil.example.test":
            findings.append(
                Finding(
                    id="logout.post_logout_redirect_open",
                    severity="high",
                    confidence="high",
                    title="Attacker-controlled post_logout_redirect_uri accepted",
                    description=(
                        "The logout endpoint redirected the user-agent to a host "
                        "not registered for this client. RPs should only accept "
                        "exact-match post_logout_redirect_uri values registered "
                        "with the client."
                    ),
                    spec_ref=(
                        "OpenID Connect RP-Initiated Logout 1.0 sec 2, 3; "
                        "OAuth 2.0 Security BCP sec 4.1 (by analogy)"
                    ),
                    poc_url=url_evil,
                    remediation=(
                        "Configure the IdP to match post_logout_redirect_uri "
                        "against the exact list registered for this client."
                    ),
                    evidence={"status_code": resp2.status_code, "location": loc2},
                )
            )

    return findings
