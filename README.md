# oauthive

OAuth 2.0 / OIDC / SAML 2.0 misconfiguration tester.

**Test your own tenant only.** Every run requires `--i-own-this-tenant "<tenant-id>"`, and that id is written into every report and log line. Major public IdPs (Google, Microsoft Entra, Okta, Auth0) are on a denylist; override with `--allow-public-provider --reason "<text>"`.

See `PLAN.md` for the full design.

## Status

Early. M1 — OIDC discovery + capabilities probe — is implemented. Everything else is stubs that raise `NotImplementedError`.

## Quickstart

```
pip install -e '.[dev]'
oauthive discover https://idp.example.com/.well-known/openid-configuration
```
