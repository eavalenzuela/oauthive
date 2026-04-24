"""Scope handling.

RFC 6749 sec 3.3 and sec 6: clients must only receive access tokens for
scopes they have been granted; refresh MUST NOT yield additional scopes.

External observations we can make at /authorize:
  - Does the IdP silently accept scopes the operator never registered?
    Many IdPs quietly drop unknown scopes rather than rejecting the request,
    which masks bugs and leaks capability info to RPs that fish. Report as
    info/low.
  - Does requesting a clearly sensitive-shaped scope (e.g. 'admin') produce
    a consent screen or an error? We can't fully tell externally since we
    don't follow into the consent UI, but we can observe whether the IdP
    still issues a code.

Scope upgrade on refresh is tested when ctx.session_factory is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context

FUZZ_SCOPES: tuple[str, ...] = (
    "admin",
    "offline_access",
    "*",
    "openid email profile groups",
    "read:all write:all",
)


class ScopeCheck:
    id = "scope"
    name = "scope handling"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            return []

        findings: list[Finding] = []
        advertised_scopes = set(getattr(ctx.discovery, "scopes_supported", []) or [])

        for scope in FUZZ_SCOPES:
            resp = await client.probe_authorization(scope=scope)
            if not resp.accepted_redirect:
                continue
            # IdP was willing to redirect back to the app with our weird scope.
            requested_set = set(scope.split())
            unexpected = requested_set - advertised_scopes if advertised_scopes else requested_set
            if not unexpected:
                continue
            severity = "medium" if "admin" in requested_set else "low"
            findings.append(
                Finding(
                    id=f"scope.undocumented_accepted.{_slug(scope)}",
                    severity=severity,
                    confidence="medium",
                    title=f"Authorization endpoint accepted undocumented scope: {scope!r}",
                    description=(
                        "The discovery document's scopes_supported list does not "
                        "include these scopes, yet the authorization endpoint "
                        "still issued a code when they were requested. Silently "
                        "dropping unknown scopes makes it difficult for RPs to "
                        "detect typos and can mask privilege mismatches; more "
                        "dangerous, IdPs that honor undocumented scopes may grant "
                        "entitlements the RP was not expected to hold."
                    ),
                    spec_ref="RFC 6749 sec 3.3",
                    poc_url=resp.location,
                    remediation=(
                        "Reject scope values that are not in "
                        "scopes_supported at /authorize. If a scope is valid, "
                        "document it in discovery."
                    ),
                    evidence={
                        "requested_scope": scope,
                        "advertised_scopes": sorted(advertised_scopes),
                    },
                )
            )

        return findings


def _slug(s: str) -> str:
    return s.replace(" ", "_").replace(":", "_").replace("*", "star")
