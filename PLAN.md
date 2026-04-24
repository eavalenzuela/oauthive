# oauthive

An OAuth 2.0 / OIDC misconfiguration tester. Walks a provider through every misconfiguration and scores the result. Acts as both a client and a malicious relying party. Produces an HTML report with PoC URLs.

## Scope

**In scope**: OAuth 2.0 / 2.1, OIDC, PKCE, refresh-token rotation, ID-token validation, logout flows. Runs against a test tenant.

**Out of scope**: brute-force, password spraying, social engineering. oauthive tests *configuration*, not credentials.

## Non-negotiables

- Python 3.11+. CLI first, HTML report second.
- Test tenant only. Refuses to run against a URL until `--i-own-this-tenant` is passed with the tenant identifier.
- Every finding includes: severity, spec reference (RFC section), PoC URL, remediation.
- Modular — each check is a standalone plugin with a common interface.

## Architecture

```
oauthive/
  cli.py
  discovery.py        # pull .well-known/openid-configuration
  client.py           # reusable OAuth client (auth flow, token exchange, refresh)
  malicious_rp.py     # mini HTTP server to play "evil relying party"
  checks/
    base.py           # Check interface
    redirect_uri.py
    pkce.py
    state.py
    nonce.py
    scope.py
    response_type.py
    id_token.py       # alg=none, weak HS256, kid injection, aud confusion
    refresh_token.py
    logout.py
    mix_up.py
  scoring.py          # severity + confidence
  report/
    html.py
    markdown.py
    json.py
```

## Check interface

```python
@dataclass
class Finding:
    id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    title: str
    description: str
    spec_ref: str                # e.g. "RFC 6749 §3.1.2"
    poc_url: str | None
    evidence: dict
    remediation: str

class Check(Protocol):
    id: str
    name: str
    async def run(self, ctx: Context) -> list[Finding]: ...
```

## Check catalog (initial)

### redirect_uri
- Exact match vs prefix match vs substring.
- Fragment confusion: `https://app.example.com/#@evil.com/`.
- Path traversal: `https://app.example.com/../@evil.com/`.
- IPv6/IDN homoglyphs accepted?
- Localhost port-wildcarding abuse.

### pkce
- Is PKCE required for public clients? For confidential?
- Does server accept auth code without `code_verifier` if `code_challenge` was sent?
- `plain` method accepted?
- Verifier reuse across code exchanges?

### state
- Flow completes without `state`?
- State reflected but not bound to session?
- State predictable (weak RNG)?

### nonce (OIDC)
- Required for implicit/hybrid flow?
- Replayed nonce accepted?
- Missing `nonce` claim in ID token?

### scope
- Scope upgrade on refresh (request more than originally granted).
- Consent-screen bypass when adding scope.
- Undocumented scopes accepted silently.

### response_type
- Mix-up attack (response from IdP A delivered to IdP B's client).
- Token leakage via implicit `response_type=token` where code flow is available.
- `response_mode=fragment` where `form_post` would be safer for sensitive flows.

### id_token
- `alg: none` accepted.
- HS256 with the provider's public key as shared secret (classic).
- `kid` header injection / JKU/X5U abuse pointing to attacker-hosted keys.
- Audience confusion: token for client A accepted by client B.
- Expired tokens accepted due to missing `exp` validation.
- `iss` mismatch tolerated.

### refresh_token
- Rotation enforced? (Detect by issuing refresh twice and checking reuse.)
- Revocation on logout?
- Refresh bound to client? (Try using client A's refresh at client B.)

### logout
- Front-channel logout: iframe behavior, CSRF on logout endpoint.
- Back-channel logout: signature validation on logout tokens.
- Session still valid at RP after IdP logout?

### mix_up
- Dynamic registration enabled? Can we register a malicious RP?
- Does the provider distinguish between IdPs in multi-IdP federations?

## Input

```
oauthive test \
  --discovery https://idp.example.com/.well-known/openid-configuration \
  --client-id oauthive-test \
  --client-secret "$OA_SECRET" \
  --redirect-uri https://localhost:8443/cb \
  --i-own-this-tenant "acme-dev" \
  --checks all \
  --out report.html
```

Or with a config file for complex flows (multi-client mix-up tests need two clients).

## Malicious RP harness

For mix-up / redirect-uri checks, oauthive spins up a local HTTPS server (self-signed; operator must trust) that plays "evil RP". It:
- Receives auth codes sent to the wrong redirect_uri.
- Logs headers, fragments, query params.
- Attempts to exchange captured codes (demonstrates impact).

## Scoring

Each finding gets a severity from a fixed rubric:
- **critical** — full account takeover achievable from an attacker-controlled RP or URL.
- **high** — token theft or scope escalation possible.
- **medium** — weakens defense in depth (e.g. missing PKCE for a confidential client).
- **low** — best-practice deviation without direct exploit path.
- **info** — configuration notable but not exploitable.

Report groups by severity, with per-check remediation.

## Report output

HTML with:
- Summary card: N critical, N high, etc.
- Per-check section: pass/fail/error + findings.
- Embedded PoC URLs (one-click reproduce in browser).
- Raw evidence (redacted tokens) collapsible.
- Export: also emit Markdown + JSON.

## CLI surface

```
oauthive discover <url>                    # print parsed discovery doc
oauthive test --discovery <url> ...        # full suite
oauthive test --checks redirect_uri,pkce   # subset
oauthive report render findings.json       # re-render report from raw results
```

## Milestones

1. **M1 — discovery + client lib**: parse `.well-known`, complete a vanilla auth-code flow.
2. **M2 — first check**: `redirect_uri` — prove the plugin harness works.
3. **M3 — PKCE + state + nonce**: the "every sane provider gets these right" baseline.
4. **M4 — id_token checks**: the juicy ones. alg=none, kid injection, audience confusion.
5. **M5 — refresh + logout**: session-lifecycle checks.
6. **M6 — mix-up + malicious RP**: the local HTTPS harness.
7. **M7 — HTML report**: pretty output + Markdown/JSON exports.

## Open questions

- How to handle providers that require DPoP or mTLS-bound tokens? Those need per-check awareness; add a capabilities probe.
- Rate limiting: IdPs often rate-limit `/token`. Default to 1 req/s, configurable.
- SAML out of scope but many shops run hybrid; mention in README, punt to a sibling tool if demand.

## Legal / ethics guard

- `--i-own-this-tenant "<id>"` required; id written into every report and log line.
- Refuses to run against Google/Microsoft/Okta/Auth0 production endpoints by default (denylist). Operator can override with `--allow-public-provider` + reason string that goes into the log.
- README spells out "this is for testing your own tenant".
