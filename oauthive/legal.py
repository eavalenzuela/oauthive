"""Tenant-id gate and public-provider denylist."""

from __future__ import annotations

from urllib.parse import urlparse

PUBLIC_PROVIDER_HOSTS: frozenset[str] = frozenset(
    {
        "accounts.google.com",
        "oauth2.googleapis.com",
        "login.microsoftonline.com",
        "login.live.com",
        "login.microsoft.com",
        "sts.windows.net",
        "appleid.apple.com",
        "github.com",
        "api.github.com",
        "www.facebook.com",
        "graph.facebook.com",
    }
)

PUBLIC_PROVIDER_SUFFIXES: tuple[str, ...] = (
    ".okta.com",
    ".oktapreview.com",
    ".auth0.com",
    ".us.auth0.com",
    ".eu.auth0.com",
    ".onelogin.com",
    ".pingidentity.com",
    ".duosecurity.com",
)


class LegalGuardError(RuntimeError):
    """Raised when the legal guard refuses to proceed."""


def host_is_public_provider(host: str) -> bool:
    h = host.lower().strip()
    if h in PUBLIC_PROVIDER_HOSTS:
        return True
    return any(h.endswith(suffix) for suffix in PUBLIC_PROVIDER_SUFFIXES)


def assert_permitted(
    target_url: str,
    tenant_id: str | None,
    *,
    allow_public_provider: bool = False,
    reason: str | None = None,
) -> None:
    """Raise LegalGuardError unless this run is allowed.

    - tenant_id must be present and non-empty.
    - If the target host is on the public-provider denylist, the operator must
      pass allow_public_provider=True AND supply a non-empty reason.
    """
    if not tenant_id or not tenant_id.strip():
        raise LegalGuardError(
            "--i-own-this-tenant is required. Pass the tenant identifier you are testing."
        )

    host = urlparse(target_url).hostname or ""
    if host_is_public_provider(host):
        if not allow_public_provider:
            raise LegalGuardError(
                f"Refusing to run against public provider host '{host}'. "
                "This tool is for testing tenants you own. If this is a dedicated "
                "tenant you own at a public provider, re-run with "
                "--allow-public-provider --reason \"<text>\"."
            )
        if not reason or not reason.strip():
            raise LegalGuardError(
                "--allow-public-provider requires --reason \"<text>\"; the reason "
                "is written into every log line and the report header."
            )
