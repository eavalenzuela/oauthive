# oauthive — Planned Improvements & Feature Roadmap

Scoping document only. This is an engineering roadmap for `oauthive` at its
current state (v0.1.0, milestones M1–M15 implemented: full OIDC + SAML check
suite, JOSE/SAML forge primitives, malicious RP/SP harness, HTML/MD/JSON
reports, Keycloak + vuln-sp fixture, 265 unit tests, CI lint + test on
py3.11–3.13). It describes *what* to invest in next and *why*. It intentionally
contains no offensive code, payloads, or attack procedures — capability areas
are referenced only at a high level.

## Improvements

1. **Enforce the rate limiter at runtime.** `RateLimitCfg`
   (`token_endpoint_rps` / `auth_endpoint_rps`) is parsed from config but no
   token-bucket, `Retry-After` handling, or per-endpoint throttle exists in the
   HTTP path — implementing it prevents accidentally hammering (self-DoS'ing) an
   operator's own IdP and is a core responsible-use control.

2. **Build the bounded-concurrency runner path.** `runner.py` still ships the
   sequential-only path its own docstring admits ("`--concurrency` … lands
   later"); wiring the documented `asyncio.Semaphore` pool for `parallel_safe`
   checks cuts wall-clock on large suites without reordering mutating checks.

3. **Persist durable, run-scoped audit logs.** `structlog` currently renders
   JSON only to stdout; the design promised `~/.oauthive/runs/<run-id>.log`.
   A security tool needs a durable, greppable trail capturing tenant id,
   authorization reason, and every request target for after-the-fact review.

4. **Add an integration test suite and wire it into CI.** Only `tests/unit/`
   exists and `ci.yml` runs just lint + `pytest -q`; the README claims CI also
   runs `fixture demo`, but it does not. A `tests/integration/` layer driving
   the Keycloak + vuln-sp fixture end-to-end (and running in CI) closes that gap
   and guards against silent check regressions.

5. **Decompose the `cli.py` monolith.** At ~1150 lines it holds every
   command (`test`, `jose`, `saml`, `report`, `fixture`, `cleanup`); splitting
   into per-command modules behind a thin Typer assembly makes commands
   independently testable and far easier to review.

6. **Harden the authorization guard.** Ensure `legal.assert_permitted` gates
   *every* network entry point (OIDC discovery, SAML metadata fetch,
   malicious-RP/SP bind, `cleanup`), add an explicit operator-declared
   owned-tenant allowlist alongside the public-provider denylist, and record the
   full authorization decision (tenant, override reason) in the report header.

7. **Introduce a typed error/exception taxonomy.** Network, TLS, timeout, and
   parse failures should map to structured `error`-type finding records with
   remediation context instead of a generic catch-all, so operators can tell a
   flaky endpoint apart from a genuine finding or a tool bug.

8. **Normalize and de-duplicate reporting output.** Add result-normalization so
   the same underlying issue surfaced by multiple checks collapses to one
   finding, enforce severity/confidence-rubric consistency, and add JSON-schema
   round-trip tests so `report render` from a prior `findings.json` is provably
   stable across versions.

9. **Improve configuration and UX ergonomics.** Env interpolation only handles
   exact `$VAR` (no `${VAR}`/defaults); add richer interpolation, document and
   validate CLI-over-config precedence, and ship an `oauthive validate-config`
   command that dry-checks a config before any live traffic.

10. **Documentation and responsible-use policy.** Add `SECURITY.md`,
    `CONTRIBUTING.md`, a written threat model, a consolidated per-check
    remediation catalog, and an explicit responsible-use policy — reducing
    misuse risk and lowering the barrier for outside contributors and reviewers.

## New Features

1. **Vendor quirks layer.** The designed `oauthive/quirks/` registry (patch
   advertised-vs-runtime capability drift, emit a `metadata_disagrees_with_runtime`
   info finding) is not yet implemented; it doubles as a "your IdP's metadata is
   misleading" detector, useful even when the drift is not itself a vulnerability.

2. **CI-friendly export formats.** Add SARIF (and/or a stable JUnit-style)
   export plus a configurable exit-code policy so teams can gate pipelines and
   ingest findings into standard code-scanning dashboards.

3. **Third-party check plugins via entry points.** The runner currently only
   directory-scans `oauthive/checks/`; exposing the documented `oauthive.checks`
   entry-point group lets organizations ship internal checks in their own
   packages without forking the tool.

4. **Broaden protocol/capability coverage behind capability gates.** Extend the
   capabilities probe and check scaffolding to adjacent surfaces already hinted
   at (e.g. PAR/JARM, backchannel logout, additional SAML bindings), each gated
   on the probe so it is skipped-with-reason where unsupported.

5. **Baseline/diff mode.** Store a per-tenant baseline of findings and, on
   subsequent runs, report only new or changed findings — letting operators
   track regressions over time and demonstrate that a remediation actually
   closed a previously reported issue.
