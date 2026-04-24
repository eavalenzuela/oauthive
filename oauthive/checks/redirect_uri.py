"""redirect_uri validation check.

Generates a family of candidate redirect URIs based on the registered one,
sends each to the authorization endpoint, and classifies how the IdP
responded. A well-configured IdP must only accept the exact registered URI;
any candidate the IdP redirects to (or returns with error+state pointing at it)
is a finding.

Classification of a single probe:
  - accepted : IdP issued a 302 whose Location targets the candidate host+path.
    For a malicious candidate this is critical -- the IdP will hand a
    user-agent (and any auth material) to attacker-controlled infrastructure.
  - rejected : IdP stayed on its own domain or returned an error without
    redirecting to the candidate. This is the safe behavior.
  - inconclusive : network error / 5xx / unparseable response. Reported as
    info with low confidence so operators can rerun.

Spec references: RFC 6749 sec 3.1.2 (redirect_uri registration and matching),
OAuth 2.0 Security Best Current Practice draft sec 4.1 (exact matching).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from .base import Finding

if TYPE_CHECKING:
    from ..context import Context


@dataclass(frozen=True)
class Candidate:
    id: str
    description: str
    severity_if_accepted: str  # severity when this one succeeds
    uri: str


def _tweak(registered: str, mutator) -> str:
    parts = urlparse(registered)
    return mutator(parts)


def candidates_for(registered: str) -> list[Candidate]:
    """Derive candidate redirect URIs from a registered one.

    Skips transformations that don't make sense for the given URL (e.g. port
    wildcards for non-localhost).
    """
    u = urlparse(registered)
    if not u.scheme or not u.hostname:
        raise ValueError(f"registered redirect_uri is not a full URL: {registered}")

    host = u.hostname
    port = u.port
    path = u.path or "/"
    scheme = u.scheme
    netloc = u.netloc

    out: list[Candidate] = [
        Candidate(
            id="exact",
            description="Registered redirect_uri exactly. Control: must be accepted.",
            severity_if_accepted="info",
            uri=registered,
        ),
        Candidate(
            id="fragment_confusion",
            description=(
                "Fragment containing '@<attacker>/' appended to path. Parsers that "
                "normalize fragments differently than the matcher can be tricked "
                "into treating this as an evil authority."
            ),
            severity_if_accepted="critical",
            uri=f"{scheme}://{netloc}{path}#@evil.example.test/",
        ),
        Candidate(
            id="path_traversal",
            description=(
                "Path traversal sequence pointing at attacker-controlled host. "
                "Classic against prefix-match validators that don't resolve the "
                "path before comparing."
            ),
            severity_if_accepted="critical",
            uri=f"{scheme}://{netloc}{path.rstrip('/')}/../@evil.example.test/",
        ),
        Candidate(
            id="userinfo_injection",
            description=(
                "Userinfo component containing the attacker host. Some libraries "
                "treat the authority as 'evil.example.test' while others treat it "
                "as the registered host."
            ),
            severity_if_accepted="high",
            uri=f"{scheme}://evil.example.test@{netloc}{path}",
        ),
        Candidate(
            id="subdomain_append",
            description=(
                "Registered host embedded as a subdomain of the attacker domain. "
                "Catches substring / suffix matchers."
            ),
            severity_if_accepted="critical",
            uri=f"{scheme}://{host}.evil.example.test{path}",
        ),
        Candidate(
            id="foreign_host",
            description="Wholly attacker-controlled host. Any acceptance is critical.",
            severity_if_accepted="critical",
            uri=f"{scheme}://evil.example.test{path}",
        ),
        Candidate(
            id="scheme_downgrade",
            description=(
                "Same host+path but http scheme (when registered was https). "
                "An IdP that ignores scheme during matching leaks the code over cleartext."
            ),
            severity_if_accepted="high" if scheme == "https" else "info",
            uri=urlunparse(("http", netloc, path, "", "", "")),
        ),
        Candidate(
            id="path_suffix",
            description=(
                "Arbitrary path suffix appended to the registered path. Catches "
                "prefix-match validators."
            ),
            severity_if_accepted="high",
            uri=f"{scheme}://{netloc}{path.rstrip('/')}/attacker-chosen-suffix",
        ),
        Candidate(
            id="query_append",
            description=(
                "Registered URL with an attacker-chosen query string. Most IdPs "
                "strip or ignore the query, but some use it in matching and then "
                "forward it unchanged."
            ),
            severity_if_accepted="medium",
            uri=f"{scheme}://{netloc}{path}?attacker=1",
        ),
    ]

    if host in ("localhost", "127.0.0.1", "::1"):
        bumped = port + 1 if port else 9999
        out.append(
            Candidate(
                id="localhost_port_wildcard",
                description=(
                    "Different localhost port. RFC 8252 sec 7.3 permits port "
                    "wildcarding for native apps on loopback, but only within "
                    "loopback; an IdP that does this must not ignore port entirely "
                    "for non-loopback hosts."
                ),
                severity_if_accepted="low",
                uri=f"{scheme}://{host}:{bumped}{path}",
            )
        )

    return out


class RedirectURICheck:
    id = "redirect_uri"
    name = "redirect_uri validation"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        client = ctx.client
        if client is None:
            # The runner builds ctx.client for OIDC runs; without it we can't probe.
            return []

        registered = client.redirect_uri
        findings: list[Finding] = []

        exact_accepted = False
        for cand in candidates_for(registered):
            resp = await client.probe_authorization(redirect_uri=cand.uri)
            ctx.log.debug(
                "redirect_uri probe",
                candidate=cand.id,
                uri=cand.uri,
                status=resp.status_code,
                location_host=resp.location_host,
                accepted=resp.accepted_redirect,
            )
            if cand.id == "exact":
                exact_accepted = resp.accepted_redirect
                if not exact_accepted:
                    findings.append(
                        Finding(
                            id="redirect_uri.exact_rejected",
                            severity="info",
                            confidence="medium",
                            title="Registered redirect_uri was not accepted",
                            description=(
                                "The registered redirect_uri itself was not accepted by "
                                "the authorization endpoint. This usually means the "
                                "client_id is wrong, the URI has drifted from what is "
                                "registered, or the IdP requires additional parameters. "
                                "Other redirect_uri findings below may therefore be "
                                "unreliable."
                            ),
                            spec_ref="RFC 6749 sec 3.1.2",
                            remediation=(
                                "Re-register this redirect_uri in the IdP's client "
                                "configuration, or update --redirect-uri to match what "
                                "is registered."
                            ),
                            evidence={
                                "status_code": resp.status_code,
                                "location": resp.location,
                                "body_excerpt": resp.body_excerpt,
                            },
                        )
                    )
                continue

            if resp.accepted_redirect:
                findings.append(
                    Finding(
                        id=f"redirect_uri.{cand.id}",
                        severity=cand.severity_if_accepted,  # type: ignore[arg-type]
                        confidence="high",
                        title=f"Authorization endpoint accepted redirect_uri: {cand.id}",
                        description=cand.description,
                        spec_ref="RFC 6749 sec 3.1.2; OAuth 2.0 Security BCP sec 4.1",
                        poc_url=_build_poc(ctx, cand.uri),
                        remediation=(
                            "Configure the IdP to perform exact-match comparison of "
                            "redirect_uri against the registered value. Reject any "
                            "variation in scheme, host, port, path, query, or fragment. "
                            "Disable prefix/substring matching features where available."
                        ),
                        evidence={
                            "candidate_uri": cand.uri,
                            "registered_uri": registered,
                            "status_code": resp.status_code,
                            "location": resp.location,
                            "location_host": resp.location_host,
                        },
                    )
                )

        if not exact_accepted and any(f.id != "redirect_uri.exact_rejected" for f in findings):
            for f in findings:
                if f.id != "redirect_uri.exact_rejected":
                    f.confidence = "medium"

        return findings


def _build_poc(ctx: "Context", redirect_uri: str) -> str | None:
    """Build a reproducer URL an operator can paste into a browser."""
    from ..client import AuthorizationRequest, build_authorization_url

    client = ctx.client
    if client is None or client.discovery.authorization_endpoint is None:
        return None
    req = AuthorizationRequest(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        state="oauthive-poc",
    )
    return build_authorization_url(str(client.discovery.authorization_endpoint), req)
