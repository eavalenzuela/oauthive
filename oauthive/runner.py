"""Check orchestrator.

M2 ships the sequential path only. --concurrency for parallel_safe checks
lands when there's a second parallel_safe check to prove the semaphore pool.
"""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import time
from dataclasses import dataclass
from typing import Iterable

import structlog

from . import __version__
from .context import Context
from .checks.base import Check, Finding
from .report.schema import CheckRecord, FindingRecord, Report, RunMetadata, now_utc


@dataclass
class RunnerConfig:
    tenant_id: str
    enabled: list[str]  # check ids, or ["all"]
    disabled: list[str]
    per_check_timeout_s: float = 30.0
    target_issuer: str | None = None
    allow_public_provider: bool = False
    allow_public_reason: str | None = None
    session_mode: str = "isolated"  # "isolated" | "fast"
    cleanup_tokens: bool = True
    # Browser driver used to bootstrap a live AuthSession when a check calls
    # ctx.ensure_session(). None means "no session available; session-dependent
    # sub-findings just won't fire".
    driver: Any = None
    bootstrap_scope: str = "openid"


def _order_for_session_mode(checks: list[Check], mode: str) -> list[Check]:
    """In fast mode, pin mutating checks (which invalidate the shared session)
    to the end so earlier checks see a live session."""
    if mode != "fast":
        return list(checks)
    # Any check that requires_fresh_auth or whose id is 'logout' / 'refresh_token'
    # is treated as session-mutating. Other checks run first.
    def _is_mutating(c: Check) -> bool:
        return c.requires_fresh_auth or c.id in {"logout", "refresh_token"}

    return sorted(checks, key=lambda c: (1 if _is_mutating(c) else 0, c.id))


def _discover_checks() -> list[Check]:
    """Scan oauthive.checks.* for modules that expose a top-level Check class.

    Entry-point plugin loading is added alongside third-party check packaging
    (post-M2). For the in-tree modules, scanning is enough.
    """
    from . import checks as checks_pkg

    found: list[Check] = []
    for info in pkgutil.iter_modules(checks_pkg.__path__):
        if info.name == "base":
            continue
        mod = importlib.import_module(f"oauthive.checks.{info.name}")
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and attr_name.endswith("Check")
                and attr_name != "Check"
            ):
                found.append(obj())
    return found


def select_checks(
    all_checks: Iterable[Check],
    enabled: list[str],
    disabled: list[str],
) -> list[Check]:
    enabled_set = set(enabled)
    disabled_set = set(disabled)
    out: list[Check] = []
    for c in all_checks:
        if c.id in disabled_set:
            continue
        if "all" in enabled_set or c.id in enabled_set:
            out.append(c)
    return out


async def _run_one(check: Check, ctx: Context, timeout_s: float) -> CheckRecord:
    start = time.perf_counter()
    try:
        findings = await asyncio.wait_for(check.run(ctx), timeout=timeout_s)
    except asyncio.TimeoutError:
        return CheckRecord(
            id=check.id,
            name=check.name,
            status="error",
            duration_s=time.perf_counter() - start,
            error=f"timed out after {timeout_s:.1f}s",
        )
    except Exception as e:  # noqa: BLE001 - checks are user-extensible
        return CheckRecord(
            id=check.id,
            name=check.name,
            status="error",
            duration_s=time.perf_counter() - start,
            error=f"{type(e).__name__}: {e}",
        )
    return CheckRecord(
        id=check.id,
        name=check.name,
        status="fail" if findings else "pass",
        duration_s=time.perf_counter() - start,
        findings=[_to_record(f) for f in findings],
    )


def _to_record(f: Finding) -> FindingRecord:
    return FindingRecord(
        id=f.id,
        severity=f.severity,
        confidence=f.confidence,
        title=f.title,
        description=f.description,
        spec_ref=f.spec_ref,
        remediation=f.remediation,
        poc_url=f.poc_url,
        evidence=f.evidence,
    )


async def run(ctx: Context, cfg: RunnerConfig) -> Report:
    started = now_utc()
    log = ctx.log.bind(tenant_id=cfg.tenant_id)

    all_checks = _discover_checks()
    selected = select_checks(all_checks, cfg.enabled, cfg.disabled)
    log.info(
        "runner.start",
        discovered=[c.id for c in all_checks],
        selected=[c.id for c in selected],
    )

    # Build a session factory that lazy-bootstraps once via the configured
    # driver. Checks call `await ctx.ensure_session()`. If no driver was
    # passed in cfg, the factory stays None and ensure_session returns None.
    if cfg.driver is not None and ctx.client is not None and ctx.session_factory is None:
        ctx.session_factory = _make_session_factory(ctx, cfg)

    selected = _order_for_session_mode(selected, cfg.session_mode)
    tags = ctx.capabilities.capability_tags()
    records: list[CheckRecord] = []

    for check in selected:
        missing = check.requires_capabilities - tags
        if missing:
            records.append(
                CheckRecord(
                    id=check.id,
                    name=check.name,
                    status="skipped",
                    duration_s=0.0,
                    skip_reason=f"missing capabilities: {sorted(missing)}",
                )
            )
            continue
        # If the check requires mTLS-bound tokens but no client cert is
        # configured, skip rather than letting the check fail at token
        # exchange with a confusing TLS error.
        if "mtls" in check.requires_capabilities:
            client = ctx.client
            if client is None or getattr(client, "mtls_cert", None) is None:
                records.append(
                    CheckRecord(
                        id=check.id,
                        name=check.name,
                        status="skipped",
                        duration_s=0.0,
                        skip_reason="requires_mtls_cert (configure client.mtls_cert/mtls_key)",
                    )
                )
                continue
        records.append(await _run_one(check, ctx, cfg.per_check_timeout_s))

    report = Report(
        metadata=RunMetadata(
            tenant_id=cfg.tenant_id,
            started_at=started,
            finished_at=now_utc(),
            tool_version=__version__,
            target_issuer=cfg.target_issuer,
            allow_public_provider=cfg.allow_public_provider,
            allow_public_reason=cfg.allow_public_reason,
        ),
        checks=records,
    )
    log.info(
        "runner.done",
        counts=report.severity_counts(),
        n_checks=len(records),
    )
    return report


def _make_session_factory(ctx: Context, cfg: RunnerConfig):
    """Return an async closure that bootstraps once and caches the session.

    Failures during bootstrap are logged and swallowed -- checks that need a
    live session should degrade gracefully when ensure_session() returns None.
    """
    cached: dict[str, Any] = {}

    async def factory(*, scope: str = cfg.bootstrap_scope, fresh: bool = False):
        if not fresh and "session" in cached:
            return cached["session"]
        try:
            session = await cfg.driver.bootstrap(ctx.client, scope=scope)
        except Exception as e:  # noqa: BLE001
            ctx.log.warning("runner.bootstrap_failed", error=f"{type(e).__name__}: {e}")
            cached["session"] = None
            return None
        cached["session"] = session
        return session

    return factory


def make_logger(tenant_id: str) -> structlog.stdlib.BoundLogger:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
    return structlog.get_logger().bind(tenant_id=tenant_id)
