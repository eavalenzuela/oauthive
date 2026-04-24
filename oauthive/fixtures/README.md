# oauthive self-test fixture

Keycloak 25 preconfigured with an intentionally misconfigured realm, for
smoke-testing oauthive against a known-bad IdP.

## Usage

```
oauthive fixture up          # docker compose up -d, wait for health
oauthive fixture demo        # run the full check suite against it
oauthive fixture down        # tear down
```

The demo asserts that expected finding ids land; a regression shows up as a
missing id rather than a spurious one.

## What the realm ships with

Realm: `oauthive-dev`

Users:
- `alice / alice-pass`

Clients:

| clientId | intent | expected oauthive findings |
|---|---|---|
| `oauthive-public-no-pkce` | Public client, PKCE not enforced, implicit flow enabled, loose redirect URIs | `pkce.not_required`, `response_type.implicit_*`, `state.iss_not_returned` |
| `oauthive-prefix-redirect` | Public client with `https://app.example.test/*` redirect URIs | `redirect_uri.path_suffix`, `redirect_uri.subdomain_append` (depending on Keycloak matcher) |
| `oauthive-confidential` | Well-configured control client | zero findings against this client in isolation |

## Known gaps

- **`alg=none` ID tokens**: Keycloak does not ship an `alg=none` signer; the
  `id_token.issued_with_alg_none` sub-finding is not exercisable against
  this fixture without a custom SPI. The discovery-level
  `id_token.none_advertised` finding is not triggered either (Keycloak
  doesn't advertise `none` in `id_token_signing_alg_values_supported`).
- **JWKS private-material leak**: Keycloak's default JWKS endpoint does
  not leak private parameters; the `id_token.jwks_exposes_private_material`
  finding is not exercisable here.
- **Dynamic registration**: disabled by default; `mix_up` findings are
  not exercisable.

For those paths, exercise `oauthive` against a purpose-built target (or
add SPI shims to this realm in your own fork).

## Ports

| service  | host binding         | purpose                              |
|----------|----------------------|--------------------------------------|
| keycloak | `127.0.0.1:8080`     | OIDC + SAML IdP                      |
| vuln-sp  | `127.0.0.1:8081`     | Deliberately-broken SAML SP for forge smoke tests |

Keycloak bootstrap admin: `admin / admin`.

## Discovery URLs

- OIDC:              `http://localhost:8080/realms/oauthive-dev/.well-known/openid-configuration`
- SAML IdP metadata: `http://localhost:8080/realms/oauthive-dev/protocol/saml/descriptor`

## Vulnerable SAML SP

`fixtures/vuln-sp/` builds a tiny Python SP with intentional bugs:

- No signature verification
- No audience restriction enforcement
- No Recipient / InResponseTo binding
- NameID extracted via textContent-style path (comment injection lands)
- No NotBefore / NotOnOrAfter enforcement

Exists so `oauthive saml forge --attack <X> | curl -d @- http://127.0.0.1:8081/acs`
always confirms the forge actually produced a SP-accepted payload.

### Keycloak SAML client

Client `http://vuln-sp.oauthive.test/saml/sp` is registered for the vuln-sp
with `client.signature=false` and `server.signature=false`, matching its
permissive posture.
