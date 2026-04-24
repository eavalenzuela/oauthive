# oauthive

An OAuth 2.0 / OIDC / SAML 2.0 misconfiguration tester. Walks a provider through every misconfiguration and scores the result. Acts as both a client/SP and a malicious relying party / service provider. Produces an HTML report with PoC URLs.

## Scope

**In scope**: OAuth 2.0 / 2.1, OIDC, PKCE, refresh-token rotation, ID-token validation, logout flows, SAML 2.0 (Web Browser SSO profile, SP-initiated and IdP-initiated, SLO). Runs against a test tenant.

**Out of scope**: brute-force, password spraying, social engineering. oauthive tests *configuration*, not credentials. WS-Federation and SAML 1.x are not covered.

## Non-negotiables

- Python 3.11+. CLI first, HTML report second.
- Test tenant only. Refuses to run against a URL until `--i-own-this-tenant` is passed with the tenant identifier.
- Every finding includes: severity, spec reference (RFC section), PoC URL, remediation.
- Modular — each check is a standalone plugin with a common interface.

## Tech stack

- **HTTP**: `httpx` (async, HTTP/2, easy proxying for debug).
- **JWT**: `PyJWT` for parsing/verification on the honest path; hand-rolled JWS encoder in `oauthive/jose/forge.py` for the malicious path (`alg=none`, HS256-with-pubkey, `kid` injection, JKU/X5U pivots). Authlib explicitly avoided — it resists the forgery patterns we need.
- **SAML / XML**: `lxml` (with `defusedxml` for any operator-supplied XML parsing on the malicious-SP receive path); honest signature verification via `signxml`. Malicious-side signing/forgery is hand-rolled in `oauthive/saml/forge.py` (signxml refuses many of the patterns we need — comment injection, XML-sig wrapping, signature stripping). `xmlsec` (libxmlsec1) optional for canonicalization correctness in forged docs.
- **CLI**: `typer` (Click underneath, type-hint-driven).
- **Config**: TOML via stdlib `tomllib`.
- **Browser automation (optional)**: `playwright` as an `oauthive[browser]` extra. Not a hard dep.
- **Cert/key tooling**: `cryptography` for self-signed cert generation and JWS forging.
- **Server (malicious RP)**: `uvicorn` + `starlette` (small, async, plays well with `httpx`).
- **Logging**: `structlog`, JSON-line output to `~/.oauthive/runs/<run-id>.log`.
- **Templates (HTML report)**: `jinja2`.

## Architecture

```
oauthive/
  __init__.py
  cli.py                 # typer app
  config.py              # TOML loader, schema (pydantic)
  context.py             # Context object passed to every check
  runner.py              # orchestrator: ordering, fresh-auth gating, concurrency
  discovery.py           # pull .well-known/openid-configuration AND SAML metadata XML
  capabilities.py        # probe: PKCE? DPoP? mTLS? par? jarm? dynamic-reg? SAML bindings? signed-requests?
  client.py              # honest OAuth client (auth flow, token exchange, refresh)
  session.py             # AuthSession: tokens + cookies + jwks cache
  jose/
    forge.py             # malicious JWS construction
    verify.py            # honest JWT verification
  saml/
    metadata.py          # parse IdP metadata (EntityDescriptor, KeyDescriptor, bindings)
    sp.py                # honest SP: build AuthnRequest, validate Response/Assertion
    forge.py             # malicious assertion/response: sig stripping, sig wrapping (XSW1-8),
                         #   comment injection, KeyInfo swap, transform abuse
    bindings.py          # HTTP-Redirect (DEFLATE+sig), HTTP-POST, HTTP-Artifact
    canon.py             # exclusive C14N helpers used by forge
  browser/
    __init__.py
    playwright_driver.py # optional; resolves auth URL → callback URL via headless login
    manual_driver.py     # default; prints URL, waits for operator paste-back
    refresh_driver.py    # bootstrap mode: obtain RT once, reuse where possible
  malicious_rp/
    server.py            # uvicorn app: receives codes, logs, attempts exchange;
                         #   also serves /saml/acs and /saml/sls for malicious-SP role
    certs.py             # generate / load self-signed (or user-provided) cert
    saml_keys.py         # signing/encryption keypair for the malicious SP
  checks/
    base.py              # Check interface, parallel_safe, requires_fresh_auth
    redirect_uri.py
    pkce.py
    state.py
    nonce.py
    scope.py
    response_type.py
    id_token.py          # alg=none, weak HS256, kid injection, aud confusion
    refresh_token.py
    logout.py
    mix_up.py
    saml_signature.py    # sig stripping; alg downgrade; KeyInfo trust
    saml_xsw.py          # XML signature wrapping (XSW1–XSW8)
    saml_assertion.py    # Conditions/NotOnOrAfter/AudienceRestriction enforcement;
                         #   SubjectConfirmation Recipient + InResponseTo binding;
                         #   replay window
    saml_xxe.py          # XXE / DTD / external-entity in parser; billion-laughs
    saml_comment.py      # NameID comment-injection account-takeover (CVE-2018-0489 family)
    saml_encryption.py   # EncryptedAssertion downgrade; CBC padding-oracle posture; key-wrap algs
    saml_metadata.py     # unsigned metadata accepted; metadata URL trust;
                         #   entityID confusion across SPs
    saml_relaystate.py   # RelayState open-redirect; missing/oversized/unsigned RelayState
    saml_slo.py          # LogoutRequest signature; session still valid post-SLO
    saml_idp_initiated.py # unsolicited Response accepted without InResponseTo
  scoring.py             # severity + confidence rubric
  report/
    html.py              # jinja2 template render
    markdown.py
    json.py              # versioned schema (schema_version: 1)
    schema.py            # pydantic models for the report
  quirks/
    __init__.py          # registry: dispatch by issuer hostname / SAML entityID
    base.py              # Quirk interface: matches(meta) -> bool; patch(caps) -> CapsDelta
    # vendor modules added reactively; empty at M1
  fixtures/
    docker-compose.yml   # Keycloak (OIDC + SAML IdP) preconfigured with intentional misconfigs
    keycloak/
      realm-export.json  # OIDC clients + SAML clients (Keycloak speaks both)
      README.md
    simplesamlphp/       # second SAML IdP for cross-IdP / metadata-trust checks
      config/
      metadata/
tests/
  unit/
  integration/           # spin up the docker-compose fixture, run full suite
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
    parallel_safe: bool          # may be run concurrently with other parallel_safe checks
    requires_fresh_auth: bool    # forces a new auth dance even in fast mode
    requires_capabilities: set[str]  # e.g. {"oidc", "refresh_token", "dynamic_registration"}

    async def run(self, ctx: Context) -> list[Finding]: ...
```

`Context` carries: discovery doc, `CapabilitiesReport`, the `OAuthClient`, the active `AuthSession` (or `None` if `requires_fresh_auth`), the `MaliciousRP` handle, the run-scoped logger, and the operator-supplied tenant id.

## Runner

- Loads enabled checks via entry points (`oauthive.checks` group) plus a directory scan of `oauthive/checks/`. Third parties can ship checks in their own packages.
- Filters by `--checks` arg and by `requires_capabilities ⊆ probe_result`.
- **Session mode** (configurable):
  - `--session-mode=isolated` (default) — every check gets its own fresh auth dance. Slow, clean.
  - `--session-mode=fast` — checks share a baseline `AuthSession` from `Context`. A check with `requires_fresh_auth=True` still gets a fresh one. Mutating checks (logout, refresh-rotation) are pinned to run last in fast mode.
- Concurrency: sequential by default. `--concurrency N` runs `parallel_safe` checks in a bounded `asyncio.Semaphore` pool; non-parallel-safe checks run sequentially between batches.
- Per-check timeout (default 30s, override per check).
- Failures are caught and recorded as a `CheckError` finding rather than aborting the run.

## Browser interaction

Default model is **bootstrap-refresh** (`refresh_driver`):
1. On first run, oauthive prints an auth URL with the union of all needed scopes.
2. Operator logs in once in their own browser.
3. The exchanged refresh token (and ID token, for `aud`/`iss` reference) is cached at `~/.oauthive/sessions/<tenant-id>.json` (mode 0600).
4. Subsequent checks mint access tokens from the RT where the flow allows; checks that need a fresh `code`/`nonce`/`state` (most of them, honestly) still trigger an interactive auth.

Optional `--browser=playwright` swaps in `playwright_driver`, which scripts the login using credentials from `[browser.credentials]` in the config file. Headless by default; `--headed` for debugging.

`--browser=manual` is the fallback that just prints URLs.

## Capabilities probe

Runs immediately after discovery. The probe handles both OIDC discovery (`.well-known/openid-configuration`) and SAML metadata (`EntityDescriptor` XML, fetched from `--saml-metadata-url` or supplied as a file). If both are present for the same tenant, the report calls them out as separate protocol surfaces sharing one `tenant_id`.

Populates a `CapabilitiesReport`:

```toml
oidc = true
pkce_supported = true
pkce_required_for_public = true   # inferred from a probe attempt
dpop_supported = false
mtls_endpoint_aliases = false
par_supported = true              # pushed authorization requests
jarm = false
dynamic_registration = false
revocation_endpoint = true
end_session_endpoint = true
backchannel_logout = false
supported_response_types = ["code", "code id_token"]
supported_response_modes = ["query", "fragment", "form_post"]
id_token_signing_algs = ["RS256", "ES256"]

[saml]
present = true
entity_id = "https://idp.example.com/saml"
sso_bindings = ["HTTP-Redirect", "HTTP-POST"]
slo_bindings = ["HTTP-Redirect"]
want_authn_requests_signed = true
sign_assertions = true
sign_responses = false
encrypt_assertions = false
nameid_formats = ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
signing_algs = ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]
digest_algs  = ["http://www.w3.org/2001/04/xmlenc#sha256"]
metadata_signed = false
metadata_url = "https://idp.example.com/saml/metadata"
```

Checks that depend on a missing capability are marked `skipped` in the report (with the reason).

## Check catalog (initial)

### redirect_uri
- Exact match vs prefix match vs substring.
- Fragment confusion: `https://app.example.com/#@evil.com/`.
- Path traversal: `https://app.example.com/../@evil.com/`.
- IPv6/IDN homoglyphs accepted?
- Localhost port-wildcarding abuse.
- *Implementation*: builds N candidate redirect URIs, sends each through the authorization endpoint, classifies response (accepted / rejected / soft-rejected). PoC URL is the offending authorization URL.

### pkce
- Is PKCE required for public clients? For confidential?
- Does server accept auth code without `code_verifier` if `code_challenge` was sent?
- `plain` method accepted?
- Verifier reuse across code exchanges?

### state
- Flow completes without `state`?
- State reflected but not bound to session?
- State predictable (weak RNG)? — request 64 codes, run NIST monobit + serial test on the concatenated state values; flag low entropy.

### nonce (OIDC)
- Required for implicit/hybrid flow?
- Replayed nonce accepted?
- Missing `nonce` claim in ID token?

### scope
- Scope upgrade on refresh (request more than originally granted).
- Consent-screen bypass when adding scope.
- Undocumented scopes accepted silently — fuzz a wordlist (`offline_access`, `admin`, `*`, `openid email profile groups`, vendor-specific).

### response_type
- Mix-up attack (response from IdP A delivered to IdP B's client).
- Token leakage via implicit `response_type=token` where code flow is available.
- `response_mode=fragment` where `form_post` would be safer for sensitive flows.

### id_token
For each: forge with `jose/forge.py`, present to a userinfo or token-introspection endpoint that claims to validate the ID token, observe behavior.
- `alg: none` accepted.
- HS256 with the provider's public key (PEM-stripped) as shared secret.
- `kid` header injection: `kid` set to a path traversal / SQLi-flavored value, JKU/X5U pointing to a key the malicious RP serves.
- Audience confusion: token for client A accepted by client B (needs the second client from config).
- Expired tokens accepted due to missing `exp` validation.
- `iss` mismatch tolerated.

### refresh_token
- Rotation enforced? (Issue refresh, exchange it, then attempt to exchange the original — should be rejected.)
- Revocation on logout? (Logout, then attempt RT exchange.)
- Refresh bound to client? (Try using client A's refresh at client B.)

### logout
- Front-channel logout: iframe behavior, CSRF on logout endpoint (no `state`/no `id_token_hint` required?).
- Back-channel logout: signature validation on logout tokens — forge one with `alg=none`, see if RP accepts.
- Session still valid at RP after IdP logout?

### mix_up
- Dynamic registration enabled? Can we register a malicious RP at runtime?
- Does the provider distinguish between IdPs in multi-IdP federations? (Requires a second discovery doc in config.)

### saml_signature
- **Sig stripping**: remove `<ds:Signature>` from a signed Response, send anyway. Many SP libs only verify *if* a signature is present.
- **Algorithm downgrade**: re-sign with `rsa-sha1` or `hmac-sha1` where the metadata advertises sha256.
- **KeyInfo trust**: swap `<KeyInfo>` to a key the malicious SP controls; SP that trusts embedded `KeyInfo` over metadata accepts.
- **Reference URI tampering**: point `<Reference URI="">` at an empty assertion; sign that; embed real malicious assertion elsewhere.

### saml_xsw
Eight classical XML Signature Wrapping variants (XSW1–XSW8 per the Somorovsky et al. taxonomy). Each builds a doc with the original signed Assertion in a position the verifier checks but the SP business logic ignores (e.g. inside a `<Extensions>` element), and a forged Assertion in the position the SP actually consumes. Per-variant PoC XML in evidence.

### saml_assertion
- `Conditions/@NotBefore` and `@NotOnOrAfter` enforced?
- `AudienceRestriction` enforced (audience confusion across SPs)?
- `SubjectConfirmationData/@Recipient` enforced (must equal ACS URL)?
- `SubjectConfirmationData/@InResponseTo` bound to outstanding `AuthnRequest@ID`?
- Replay: send the same valid assertion twice within the validity window — accepted?
- Clock skew: how far past `NotOnOrAfter` is still accepted?

### saml_xxe
- DOCTYPE / entity expansion accepted by the IdP's `AuthnRequest` parser? (Send a malicious `AuthnRequest` to the IdP's SSO endpoint with an external entity referencing `file:///etc/passwd` or an OOB DNS callback.)
- Billion-laughs / quadratic-blowup tolerance.
- Parameter entities. (Defensive note: oauthive's *own* parser uses `defusedxml`; we only test what the IdP accepts.)

### saml_comment
NameID comment-injection: `<NameID>admin@victim.com<!---->.attacker.com</NameID>` — vulnerable parsers concatenate text-node siblings differently than the canonicalizer that fed the signature. CVE-2018-0489 family. Tests both NameID and any signed text-node attribute the SP keys on.

### saml_encryption
- If `EncryptedAssertion` is supported: downgrade — strip encryption and send plaintext, see if SP accepts.
- Key-wrap algorithm: `rsa-1_5` accepted? (Bleichenbacher posture.)
- Block cipher mode: CBC vs GCM. CBC + verbose error responses → padding-oracle indication (probe but do not exploit by default; gated behind `--deep-saml`).
- Key confusion: encrypt to one SP's cert, deliver to another.

### saml_metadata
- Unsigned metadata accepted? (Replace IdP metadata mid-flight with attacker's.)
- Metadata fetched over HTTP, not HTTPS?
- `entityID` collision across SPs registered at the same IdP.
- `validUntil` honored?

### saml_relaystate
- RelayState reflected unvalidated → open redirect.
- RelayState >80 bytes accepted (spec ceiling)?
- RelayState integrity protected? (Most IdPs don't; flag as `info` unless the SP claims to.)

### saml_slo
- `LogoutRequest` accepted unsigned?
- After successful SLO, is the SP session still valid?
- `LogoutResponse` `InResponseTo` enforced?

### saml_idp_initiated
- Unsolicited Response (no prior `AuthnRequest`, no `InResponseTo`) accepted? Often intentional, but should be an explicit configuration flag — test by sending an unsolicited Response and observing whether it logs the SP user in.

## Input

CLI:
```
oauthive test \
  --discovery https://idp.example.com/.well-known/openid-configuration \
  --saml-metadata https://idp.example.com/saml/metadata \
  --client-id oauthive-test \
  --client-secret "$OA_SECRET" \
  --redirect-uri https://localhost:8443/cb \
  --saml-acs https://localhost:8443/saml/acs \
  --saml-entity-id https://localhost:8443/saml/sp \
  --i-own-this-tenant "acme-dev" \
  --checks all \
  --session-mode fast \
  --concurrency 4 \
  --browser refresh \
  --out report.html
```

Either `--discovery` or `--saml-metadata` (or both) must be supplied. Checks whose `requires_capabilities` includes `oidc` are skipped if no discovery doc; checks requiring `saml` are skipped if no metadata.

Config file (`oauthive.toml`) for complex flows:
```toml
tenant_id = "acme-dev"

[discovery]
url = "https://idp.example.com/.well-known/openid-configuration"

[client.primary]
client_id  = "oauthive-test"
client_secret = "$OA_SECRET"   # env var interpolation
redirect_uri = "https://localhost:8443/cb"

[client.secondary]              # for audience-confusion + mix-up
client_id = "oauthive-test-b"
redirect_uri = "https://localhost:8443/cb-b"

[saml]
metadata_url = "https://idp.example.com/saml/metadata"   # or metadata_file = "..."
sp_entity_id = "https://localhost:8443/saml/sp"
acs_url = "https://localhost:8443/saml/acs"
sls_url = "https://localhost:8443/saml/sls"
sign_authn_requests = true
sp_signing_key  = "~/.oauthive/saml/sp.key"
sp_signing_cert = "~/.oauthive/saml/sp.crt"

[saml.secondary]                # second SP for audience-confusion / encryption-confusion
sp_entity_id = "https://localhost:8443/saml/sp-b"
acs_url = "https://localhost:8443/saml/acs-b"

[browser]
mode = "playwright"             # "refresh" | "manual" | "playwright"
headless = true

[browser.credentials]
username = "$OA_TEST_USER"
password = "$OA_TEST_PASS"
totp_secret = "$OA_TEST_TOTP"   # optional

[malicious_rp]
listen = "https://localhost:8443"
cert = "~/.oauthive/certs/rp.pem"   # if absent, generate
key  = "~/.oauthive/certs/rp.key"

[runner]
session_mode = "isolated"
concurrency = 1
per_check_timeout_s = 30

[checks]
enabled = ["all"]
disabled = ["mix_up"]            # opt out

[rate_limit]
token_endpoint_rps = 1.0
auth_endpoint_rps  = 2.0
```

## Malicious RP / SP harness

For mix-up / redirect-uri / JKU / SAML-confusion checks, oauthive spins up a local HTTPS server that plays "evil RP" *and* "evil SP". It:
- Receives auth codes sent to the wrong redirect_uri.
- Logs headers, fragments (via a one-line JS bounce that posts the fragment back), query params.
- Attempts to exchange captured codes against the IdP (demonstrates impact in the report).
- Serves an attacker-controlled JWKS at `/jwks.json` for `kid`/JKU/X5U checks.
- Serves SAML SP metadata at `/saml/metadata` (signed with the malicious SP's key).
- Hosts `/saml/acs` and `/saml/sls` to receive Responses / LogoutRequests sent to the wrong SP.
- Captures full POST bodies (base64-encoded `SAMLResponse`) and replays them — possibly cross-SP — to demonstrate audience-confusion impact.

**Cert handling**: user-configurable.
- If `[malicious_rp].cert`/`.key` are set, use them.
- If absent, oauthive prompts on first run: *"Generate self-signed cert at `~/.oauthive/certs/rp.{pem,key}`? You will need to trust it in your browser / OS keychain. [y/N]"* — never auto-generates silently.
- Generation uses `cryptography`, SAN includes `localhost` + the configured listen host.

## Scoring

Each finding gets a severity from a fixed rubric:
- **critical** — full account takeover achievable from an attacker-controlled RP or URL.
- **high** — token theft or scope escalation possible.
- **medium** — weakens defense in depth (e.g. missing PKCE for a confidential client).
- **low** — best-practice deviation without direct exploit path.
- **info** — configuration notable but not exploitable.

Confidence is independent: `high` if the check observed an exploitable response, `medium` if behavior is suspicious but the impact wasn't fully demonstrated, `low` if inferred from missing capability.

Report groups by severity, with per-check remediation.

## Report output

HTML (jinja2 template) with:
- Summary card: N critical, N high, etc.
- Per-check section: `pass` / `fail` / `error` / `skipped` + findings.
- Embedded PoC URLs (one-click reproduce in browser).
- Raw evidence (tokens redacted to `eyJ…<sha256[:8]>…<sig8>`) collapsible.
- Export: also emit `report.md` and `report.json`.

JSON schema is versioned (`schema_version: 1`) and stable — `oauthive report render findings.json` re-renders without re-running checks.

## CLI surface

```
oauthive discover <url>                            # print parsed discovery doc + capabilities probe
oauthive saml-discover <metadata-url-or-file>      # print parsed SAML metadata + capabilities
oauthive test --discovery <url> ...                # full suite (OIDC)
oauthive test --saml-metadata <url> ...            # full suite (SAML)
oauthive test --discovery <url> --saml-metadata <url> ...   # both protocols, one report
oauthive test --checks redirect_uri,saml_xsw       # subset
oauthive report render findings.json               # re-render report from raw results
oauthive fixture up                                # docker-compose up the self-test fixture
oauthive fixture down
oauthive fixture demo                              # run the suite against the fixture (smoke test)
oauthive cleanup <run-id>                          # revoke tokens still on disk from a prior --no-cleanup run
```

## Self-test fixture

`oauthive/fixtures/docker-compose.yml` brings up Keycloak (acts as both OIDC IdP and SAML IdP) plus a SimpleSAMLphp instance for a second SAML IdP, all preconfigured to *intentionally* exhibit a known subset of misconfigs:

OIDC:
- A public client without PKCE required.
- A client with prefix-match redirect URIs.
- A client that accepts `alg=none` ID tokens (via a custom mapper / SPI shim).
- Refresh tokens without rotation.
- An end-session endpoint that doesn't require `id_token_hint`.

SAML (via a tiny purpose-built vulnerable SP container under `fixtures/vuln-sp/`):
- An SP that doesn't enforce `Audience`.
- An SP that doesn't enforce `Recipient` / `InResponseTo`.
- An SP whose XML parser is vulnerable to NameID comment injection.
- An IdP (Keycloak SAML client config) that doesn't sign Responses, only Assertions, enabling sig-stripping demos.
- A second SP whose entityID overlaps via path prefix.

Used by `tests/integration/` and by `oauthive fixture demo` for operator confidence-building. CI runs the demo on every PR; the report is asserted to contain the expected finding ids.

## Milestones

1. **M1 — discovery + client lib + capabilities probe**: parse `.well-known`, complete a vanilla auth-code flow, populate `CapabilitiesReport`.
2. **M2 — runner + first check**: `redirect_uri` end-to-end. Proves the plugin harness, `Context`, and report emission.
3. **M3 — session modes + browser drivers**: isolated vs fast; refresh + manual drivers (Playwright deferred behind extra).
4. **M4 — PKCE + state + nonce + scope + response_type**: the "every sane provider gets these right" baseline.
5. **M5 — id_token checks + JOSE forge module**: the juicy ones. alg=none, kid injection, audience confusion, JKU pivot.
6. **M6 — refresh + logout**: session-lifecycle checks; mutating-check ordering in fast mode.
7. **M7 — mix-up + malicious RP server**: the local HTTPS harness, dynamic registration probe.
8. **M8 — HTML report + Markdown/JSON exports + `report render`**: jinja2 template, versioned JSON schema.
9. **M9 — Keycloak fixture + CI integration**: docker-compose, intentional OIDC misconfigs, smoke-test assertions.
10. **M10 — SAML metadata + honest SP**: parse `EntityDescriptor`, complete a vanilla SP-initiated flow against the fixture.
11. **M11 — SAML signature + assertion checks**: `saml_signature`, `saml_assertion`, `saml_relaystate`, `saml_idp_initiated`.
12. **M12 — SAML XSW + comment-injection + XXE**: `saml_xsw` (all 8 variants), `saml_comment`, `saml_xxe`. The juicy SAML ones.
13. **M13 — SAML encryption + SLO + metadata trust**: `saml_encryption`, `saml_slo`, `saml_metadata`.
14. **M14 — Malicious SP + SimpleSAMLphp fixture + vuln-sp container**: the SAML half of the harness; SAML CI smoke test.
15. **M15 — Playwright driver, DPoP/mTLS awareness, polish**.

## Rate limiting

Token-bucket per endpoint kind (`auth`, `token`, `userinfo`, `revocation`). Defaults: `token=1.0 rps`, `auth=2.0 rps`. Configurable in `[rate_limit]`. On `429`, honors `Retry-After`; logs the throttle event.

## DPoP / mTLS handling

Capabilities probe detects both. If DPoP is required, checks that mint tokens use a per-session DPoP key (generated, stored only in memory). If mTLS is required, the operator must supply `[client.primary].mtls_cert` / `mtls_key`; checks that don't honor it are marked `skipped` with reason `requires_mtls_cert`.

## Quirks layer

`oauthive/quirks/` holds vendor-specific modules (`google.py`, `entra.py`, `okta.py`, `auth0.py`, `keycloak.py`, `adfs.py`, `pingfederate.py` — added reactively, none shipped at M1) that patch capability inference where the discovery doc or SAML metadata lies about real runtime behavior.

Each quirk implements:

```python
class Quirk(Protocol):
    id: str                                    # e.g. "okta-pkce-plain-fallback"
    vendor: str                                # human label for the report
    def matches(self, caps: CapabilitiesReport) -> bool: ...
    def patch(self, caps: CapabilitiesReport) -> CapsDelta: ...
```

The registry runs after the capabilities probe and before the runner. A quirk that fires:
1. Mutates `CapabilitiesReport` so dependent checks see reality, not the advertised doc.
2. **Emits an `info`-severity finding** of its own: `metadata_disagrees_with_runtime` — title `"<vendor> advertises X but the quirks layer knows it actually does Y"`, with `evidence` containing the advertised value, the patched value, and a link to the quirk module's source comment explaining how we learned this. This makes the quirks layer double as a "your IdP's metadata is misleading" detector — useful even when the underlying behavior isn't itself a vulnerability.

Quirks are matched by issuer hostname (OIDC) or SAML entityID, with an opt-out flag `--no-quirks` for operators who want to see the raw metadata-driven behavior.

## Cleanup policy

At the end of a run, oauthive performs **token cleanup only** by default:

- Every access token and refresh token minted during the run is sent to the IdP's `revocation_endpoint` (OAuth) or invalidated via `LogoutRequest` (SAML). Revocation failures are caught, logged, and surfaced in a `cleanup_report` block of the JSON output — they never appear as findings and never abort the run.
- **Dynamically registered clients are left in place.** Silently deleting them could mask a separate finding (some IdPs allow arbitrary client deletion via the registration access token), and most operators need to verify and remove them through their admin console anyway. The report lists every dynamically registered `client_id` / SAML `entityID` under a `dynamic_registrations` block so the operator can clean up manually.
- `--no-cleanup` retains the tokens as well — useful when the operator wants to poke at evidence (`curl` a leaked access token, replay a captured SAML assertion) after the run finishes. The report banner is then marked `LIVE TOKENS RETAINED — run "oauthive cleanup <run-id>" when done`.
- `oauthive cleanup <run-id>` is a separate command that revokes any tokens still on disk for a prior run.

## Open questions (remaining)

None — plan is ready to implement.

## Legal / ethics guard

- `--i-own-this-tenant "<id>"` required; id written into every report and log line.
- Refuses to run against Google/Microsoft/Okta/Auth0 production endpoints by default (denylist of issuer hostnames in `oauthive/legal.py`). Operator can override with `--allow-public-provider` + `--reason "<text>"` that goes into the log and the report header.
- README spells out "this is for testing your own tenant".
- Malicious-RP server binds to `127.0.0.1` / `::1` only by default; refuses to bind a public interface without `--allow-public-bind`.
