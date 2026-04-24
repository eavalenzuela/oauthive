"""ID-token posture.

Two categories:
  (a) IdP-side: advertised-algorithm hygiene, JWKS reachability, private-
      material leaks. Fully observable from discovery + a JWKS fetch.
  (b) Session-dependent: when a real id_token is available, decode it and
      inspect claims + the signature path. Lands when ctx.ensure_session()
      returns a session with an id_token.

RP-side validation (does your RP accept alg=none / HS256-with-pubkey / mangled
kid?) is tested out-of-band: forge a token with `oauthive jose forge` and
feed it to your RP. See PLAN.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..jose.verify import VerifyError, fetch_jwks, inspect_claims, unsafe_decode
from .base import Finding

if TYPE_CHECKING:
    from ..context import Context

WEAK_ALGS = {"none", "None", "NONE"}
SYMMETRIC_ALGS = {"HS256", "HS384", "HS512"}


class IDTokenCheck:
    id = "id_token"
    name = "ID token posture"
    parallel_safe = True
    requires_fresh_auth = False
    requires_capabilities = frozenset({"oidc"})

    async def run(self, ctx: "Context") -> list[Finding]:
        if ctx.discovery is None:
            return []
        findings: list[Finding] = []

        advertised = set(ctx.capabilities.oidc.id_token_signing_algs)
        if advertised & WEAK_ALGS:
            findings.append(
                Finding(
                    id="id_token.none_advertised",
                    severity="critical",
                    confidence="high",
                    title="Discovery advertises 'none' in id_token_signing_alg_values_supported",
                    description=(
                        "A compliant IdP advertises only real signing algorithms. "
                        "Listing 'none' declares that the IdP is willing to issue "
                        "unsigned ID tokens, which RFC 8725 sec 3.1 explicitly "
                        "prohibits in production."
                    ),
                    spec_ref="OpenID Connect Discovery sec 3 + RFC 8725 sec 3.1",
                    remediation=(
                        "Remove 'none' from id_token_signing_alg_values_supported "
                        "and ensure the IdP refuses to issue alg=none tokens."
                    ),
                    evidence={"advertised": sorted(advertised)},
                )
            )

        if advertised and advertised.issubset(SYMMETRIC_ALGS):
            findings.append(
                Finding(
                    id="id_token.only_symmetric_algs",
                    severity="medium",
                    confidence="high",
                    title="IdP only advertises symmetric ID-token signing algorithms",
                    description=(
                        "HS256/384/512 require the RP and the IdP to share a "
                        "secret. Every RP with the secret can mint ID tokens for "
                        "any other RP at this IdP. Production OIDC should use "
                        "asymmetric signatures (RS256 / ES256 / EdDSA)."
                    ),
                    spec_ref="RFC 8725 sec 3.5 and 3.6; OIDC Core sec 10",
                    remediation=(
                        "Enable at least one asymmetric algorithm and make it the "
                        "default; deprecate HS-based clients."
                    ),
                    evidence={"advertised": sorted(advertised)},
                )
            )

        if ctx.discovery.jwks_uri is None and "oidc" in ctx.capabilities.capability_tags():
            findings.append(
                Finding(
                    id="id_token.no_jwks_uri",
                    severity="high",
                    confidence="high",
                    title="Discovery document does not expose a jwks_uri",
                    description=(
                        "OIDC Discovery 1.0 sec 3 REQUIRES jwks_uri. Without it, "
                        "RPs cannot verify ID-token signatures."
                    ),
                    spec_ref="OpenID Connect Discovery 1.0 sec 3",
                    remediation="Expose the JWKS at a stable HTTPS URL.",
                    evidence={"discovery_keys": list(ctx.discovery.model_dump().keys())},
                )
            )
        else:
            jwks_findings = await _probe_jwks(ctx)
            findings.extend(jwks_findings)

        # Session-dependent sub-findings: decode a real id_token if we have one.
        session = await ctx.ensure_session() if ctx.session_factory else None
        if session and getattr(session, "id_token", None):
            findings.extend(_inspect_real_id_token(ctx, session.id_token))

        return findings


async def _probe_jwks(ctx: "Context") -> list[Finding]:
    findings: list[Finding] = []
    uri = ctx.discovery.jwks_uri  # type: ignore[union-attr]
    if uri is None:
        return findings
    try:
        doc = await fetch_jwks(str(uri), client=ctx.http)
    except VerifyError as e:
        findings.append(
            Finding(
                id="id_token.jwks_unreachable",
                severity="high",
                confidence="high",
                title="Advertised jwks_uri is unreachable or malformed",
                description=(
                    "Discovery advertises a jwks_uri but it could not be "
                    "retrieved or parsed. RPs that follow discovery cannot "
                    "verify signatures."
                ),
                spec_ref="OpenID Connect Discovery 1.0 sec 3",
                remediation="Serve the JWKS at the advertised URL over HTTPS.",
                evidence={"error": str(e), "jwks_uri": str(uri)},
            )
        )
        return findings

    keys = doc.get("keys", []) or []
    if not keys:
        findings.append(
            Finding(
                id="id_token.jwks_empty",
                severity="high",
                confidence="high",
                title="JWKS document has no keys",
                description="jwks_uri returned a 'keys' array with zero entries.",
                spec_ref="RFC 7517 sec 5",
                remediation="Publish the active signing key in the JWKS.",
                evidence={"jwks_uri": str(uri)},
            )
        )

    missing_kids = [k for k in keys if "kid" not in k]
    if missing_kids and len(keys) > 1:
        findings.append(
            Finding(
                id="id_token.jwks_missing_kids",
                severity="low",
                confidence="high",
                title="JWKS publishes multiple keys without 'kid'",
                description=(
                    "When multiple keys are published, RPs must rely on the "
                    "token's 'kid' header to pick the right one. Keys without a "
                    "'kid' force key-by-trial verification, which is slower and "
                    "makes rotation riskier."
                ),
                spec_ref="RFC 7517 sec 4.5",
                remediation="Assign each JWKS key a stable unique 'kid'.",
                evidence={"n_keys": len(keys), "n_missing_kid": len(missing_kids)},
            )
        )

    leaks: list[str] = []
    for k in keys:
        kty = k.get("kty")
        if kty == "RSA" and ("d" in k or "p" in k or "q" in k):
            leaks.append(k.get("kid", "<unknown>"))
        if kty in ("EC", "OKP") and "d" in k:
            leaks.append(k.get("kid", "<unknown>"))
    if leaks:
        findings.append(
            Finding(
                id="id_token.jwks_exposes_private_material",
                severity="critical",
                confidence="high",
                title="JWKS endpoint exposes private key parameters",
                description=(
                    "The public JWKS document includes private parameters ('d' "
                    "and/or RSA 'p'/'q'). Anyone who has fetched this document "
                    "can sign valid tokens as the IdP."
                ),
                spec_ref="RFC 7517 sec 4.6 / RFC 7518 sec 6",
                remediation=(
                    "ROTATE every signing key that appeared in this document "
                    "and audit for misuse. Publish only the public half "
                    "thereafter."
                ),
                evidence={"leaked_kids": leaks},
            )
        )

    return findings


def _inspect_real_id_token(ctx: "Context", token: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        decoded = unsafe_decode(token)
    except VerifyError:
        # Malformed tokens from the IdP are a finding in themselves, but
        # distinguishing from transport errors is messy; skip for now.
        return findings

    if decoded.header.get("alg") in WEAK_ALGS:
        findings.append(
            Finding(
                id="id_token.issued_with_alg_none",
                severity="critical",
                confidence="high",
                title="IdP issued an ID token with alg=none",
                description=(
                    "The live ID token the IdP minted for this client uses the "
                    "unsigned 'none' algorithm. Any RP accepting it trusts "
                    "untampered content that anyone can produce."
                ),
                spec_ref="RFC 8725 sec 3.1",
                remediation="Configure the IdP to always sign ID tokens.",
                evidence={"header": decoded.header},
            )
        )

    hygiene = inspect_claims(decoded.claims)
    for required in ("has_iss", "has_aud", "has_exp", "has_iat", "has_sub"):
        if not hygiene[required]:
            claim = required.removeprefix("has_")
            findings.append(
                Finding(
                    id=f"id_token.missing_claim.{claim}",
                    severity="high",
                    confidence="high",
                    title=f"ID token is missing required claim: {claim}",
                    description=(
                        f"OIDC Core sec 2 / 3.1.3.7 requires '{claim}' in every "
                        "ID token. The token this IdP issued for the client "
                        "does not include it."
                    ),
                    spec_ref="OpenID Connect Core 1.0 sec 2",
                    remediation=(
                        f"Configure the IdP's token mapper so that '{claim}' "
                        "is always present."
                    ),
                    evidence={"present_keys": sorted(decoded.claims.keys())},
                )
            )

    if hygiene["exp_in_past"]:
        findings.append(
            Finding(
                id="id_token.expired_on_issuance",
                severity="high",
                confidence="high",
                title="ID token 'exp' is in the past at issuance",
                description=(
                    "The IdP issued an ID token whose 'exp' is already in the "
                    "past. RPs that ignore 'exp' silently accept it; RPs that "
                    "honor it reject even legitimate logins."
                ),
                spec_ref="OpenID Connect Core 1.0 sec 3.1.3.7 (#9)",
                remediation="Fix the IdP clock / exp offset so future-dated exp is used.",
                evidence={"claims_exp": decoded.claims.get("exp")},
            )
        )

    client_id = getattr(ctx.client, "client_id", None)
    aud = decoded.claims.get("aud")
    if client_id and aud and aud != client_id and (isinstance(aud, list) and client_id not in aud):
        findings.append(
            Finding(
                id="id_token.aud_mismatch",
                severity="high",
                confidence="high",
                title="ID token 'aud' does not contain this client's client_id",
                description=(
                    "OIDC Core sec 3.1.3.7 (#3) requires 'aud' to contain the "
                    "client_id that asked for the token. This IdP issued a "
                    "token whose audience does not include our client_id."
                ),
                spec_ref="OpenID Connect Core 1.0 sec 3.1.3.7 (#3)",
                remediation=(
                    "Check the IdP's client configuration; ensure aud is set "
                    "to the client_id of the requesting client."
                ),
                evidence={"aud": aud, "expected_client_id": client_id},
            )
        )

    expected_iss = str(ctx.discovery.issuer) if ctx.discovery else None  # type: ignore[union-attr]
    iss = decoded.claims.get("iss")
    if expected_iss and iss and iss.rstrip("/") != expected_iss.rstrip("/"):
        findings.append(
            Finding(
                id="id_token.iss_mismatch",
                severity="high",
                confidence="high",
                title="ID token 'iss' does not match discovery.issuer",
                description=(
                    "The 'iss' claim must match the issuer identifier of the "
                    "OP that issued the token (OIDC Core 3.1.3.7 #1)."
                ),
                spec_ref="OpenID Connect Core 1.0 sec 3.1.3.7 (#1)",
                remediation=(
                    "Fix the IdP's issuer URL configuration so it matches "
                    "discovery."
                ),
                evidence={"iss": iss, "discovery_issuer": expected_iss},
            )
        )

    return findings
