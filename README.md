# oauthive

OAuth 2.0 / OIDC / SAML 2.0 misconfiguration tester. Acts as a client and as a
malicious relying party / service provider. Produces a severity-ranked HTML
report with PoC URLs.

**Test your own tenant only.** Every run requires `--i-own-this-tenant
"<tenant-id>"`, and that id is written into every report and log line. Major
public IdPs (Google, Microsoft Entra, Okta, Auth0, etc.) are on a denylist;
override with `--allow-public-provider --reason "<text>"`.

See `PLAN.md` for the full design.

## Install

```
pip install -e '.[dev]'
# Optional, for the Playwright browser driver:
pip install -e '.[browser]'
playwright install chromium
```

Python 3.11+.

## Quick start

Inspect an IdP:

```
oauthive discover https://idp.example.com/.well-known/openid-configuration
oauthive saml-discover https://idp.example.com/saml/metadata
```

Run the OIDC suite:

```
oauthive test \
  --discovery https://idp.example.com/.well-known/openid-configuration \
  --client-id oauthive-test \
  --redirect-uri https://app.example.test/cb \
  --i-own-this-tenant "acme-dev" \
  --out report.html
```

Run the SAML suite:

```
oauthive test \
  --saml-metadata https://idp.example.com/saml/metadata \
  --i-own-this-tenant "acme-dev" \
  --out report.html
```

Both at once (recommended when the tenant speaks both protocols):

```
oauthive test \
  --discovery https://idp.example.com/.well-known/openid-configuration \
  --saml-metadata https://idp.example.com/saml/metadata \
  --client-id oauthive-test --redirect-uri https://app.example.test/cb \
  --i-own-this-tenant "acme-dev" \
  --out report.html
```

Three files land: `report.html`, `report.md`, `findings.json` (versioned). Use
`oauthive report render findings.json --out report.html` to re-render from a
prior run without re-querying the IdP.

Non-zero exit when at least one `critical` or `high` finding lands.

## JOSE / SAML tooling

For SP-side testing, oauthive ships forge primitives you drive by hand:

```
oauthive jose decode <jwt>
oauthive jose forge --attack alg_none --from-token <id_token>
oauthive jose forge --attack hs256_pubkey --public-key-pem idp.pem --from-token <id_token>
oauthive jose forge --attack jku_pivot --jku https://evil.example.test/jwks.json \
    --from-token <id_token> --attacker-jwks-out /tmp/jwks.json

oauthive saml decode <metadata-or-response.xml>
oauthive saml forge --attack strip_signature --from-file captured-response.xml
oauthive saml forge --attack xsw3 --from-file captured-response.xml --evil-name-id admin@victim.test
oauthive saml forge --attack inject_nameid_comment --from-file captured-response.xml --victim admin@victim.test
oauthive saml forge --attack xxe_external_entity --oob-url http://127.0.0.1:8443/cb \
    --issuer <sp> --acs-url <acs> --destination <sso>
oauthive saml forge --attack build_logout_request \
    --issuer <sp> --destination <slo> --name-id alice@example.test
```

Output goes to stdout; operators pipe into `curl` against their own
RP/SP/IdP for impact validation.

## Self-test fixture

```
oauthive fixture up       # docker compose up -d: Keycloak + intentionally-broken vuln-sp
oauthive fixture demo     # run the full suite, assert expected finding ids land
oauthive fixture down     # docker compose down -v
```

In `--strict` mode (default) `fixture demo` exits non-zero when any expected
finding is missing -- use this in CI to catch regressions.

## Check catalog

| id                        | severity range | what it looks at                                                        |
|---------------------------|----------------|--------------------------------------------------------------------------|
| `redirect_uri`            | info..critical | 9+ redirect-uri-match tricks; flags anything the IdP redirects the UA to |
| `pkce`                    | low..high      | PKCE required? `plain` accepted? malformed challenge accepted?           |
| `state`                   | info..medium   | state omitted accepted; `iss` in callback (RFC 9207)                     |
| `nonce`                   | high           | nonce omitted for hybrid/implicit still issues ID token                  |
| `scope`                   | low..medium    | undocumented scopes silently honored                                     |
| `response_type`           | info..high     | implicit advertised / issues tokens; fragment vs form_post               |
| `id_token`                | low..critical  | `alg=none` advertised, weak algs only, JWKS reachable + hygiene, live id_token claim validation |
| `refresh_token`           | info..critical | rotation enforced, cross-client binding (needs secondary client)          |
| `logout`                  | info..high     | end_session surface: id_token_hint, post_logout_redirect_uri, single-sign-out support |
| `mix_up` (OIDC)           | high..critical | dynamic registration accepts anonymous POSTs and attacker jwks_uri       |
| `dpop`                    | info..low      | DPoP + mTLS binding posture; exercise-pointer for sender-constrained-token enforcement |
| `saml_signature`          | low..high      | IdP WantAuthnRequestsSigned, signing cert hygiene (key size, sig alg, expiry) |
| `saml_assertion`          | low..medium    | SP WantAssertionsSigned, metadata signed                                  |
| `saml_xsw`                | info           | exercise XSW1-XSW8 against your SP (forge + curl)                         |
| `saml_comment`            | info           | exercise NameID comment injection against your SP                         |
| `saml_xxe`                | info           | exercise XXE / DTD / entity handling against your IdP's AuthnRequest parser |
| `saml_encryption`         | info..high     | rsa-1_5 key wrap advertised, CBC modes, weak encryption key, exercise pointer |
| `saml_slo`                | info..medium   | SingleLogoutService present, exercise pointer for unsigned LogoutRequest  |
| `saml_metadata`           | low..high      | metadata fetched over HTTP, validUntil expired / absent                   |
| `saml_relaystate`         | info           | exercise RelayState enforcement against your SP                           |
| `saml_idp_initiated`      | info           | exercise unsolicited-Response handling against your SP                    |

## Config file

Full example at `PLAN.md` under "Input". Minimal:

```toml
tenant_id = "acme-dev"

[discovery]
url = "https://idp.example.com/.well-known/openid-configuration"

[client.primary]
client_id = "oauthive-test"
client_secret = "$OA_SECRET"          # env-var interpolation
redirect_uri = "https://127.0.0.1:8443/cb"

[saml]
metadata_url = "https://idp.example.com/saml/metadata"
sp_entity_id = "https://127.0.0.1:8443/saml/sp"
acs_url = "https://127.0.0.1:8443/saml/acs"
```

## Developing

```
pip install -e '.[dev]'
pytest -q
```

270+ tests run in under 3 seconds. CI also runs `oauthive fixture demo` which
takes closer to 30s because of Keycloak startup.

Legal / ethics guard is in `oauthive/legal.py`. Malicious-RP server refuses
to bind public interfaces by default. Token cleanup revokes any ATs/RTs
minted during a run; `--no-cleanup` retains them with a banner.
