"""Stdout summary renderer.

Full HTML / Markdown arrive in M8. Text rendering is enough for M2 to prove
the runner is producing useful output.
"""

from __future__ import annotations

import typer

from .schema import Report

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": typer.colors.BRIGHT_RED,
    "high": typer.colors.RED,
    "medium": typer.colors.YELLOW,
    "low": typer.colors.BLUE,
    "info": typer.colors.CYAN,
}


def render(report: Report) -> None:
    counts = report.severity_counts()
    typer.secho(
        f"\noauthive run: tenant={report.metadata.tenant_id}  issuer={report.metadata.target_issuer}",
        bold=True,
    )
    total = sum(counts.values())
    summary = "  ".join(
        typer.style(f"{sev}:{counts[sev]}", fg=_SEV_COLOR[sev], bold=counts[sev] > 0)
        for sev in _SEV_ORDER
    )
    typer.echo(f"findings: {summary}   (total={total})\n")

    for check in report.checks:
        status_color = {
            "pass": typer.colors.GREEN,
            "fail": typer.colors.RED,
            "error": typer.colors.BRIGHT_RED,
            "skipped": typer.colors.BRIGHT_BLACK,
        }[check.status]
        typer.secho(
            f"[{check.status:^7}] {check.id:24} {check.name}  ({check.duration_s:.2f}s)",
            fg=status_color,
        )
        if check.error:
            typer.secho(f"          error: {check.error}", fg=typer.colors.RED)
        if check.skip_reason:
            typer.secho(f"          skipped: {check.skip_reason}", fg=typer.colors.BRIGHT_BLACK)
        for f in check.findings:
            color = _SEV_COLOR[f.severity]
            typer.secho(f"    - [{f.severity:>8}] {f.id}  {f.title}", fg=color)
            if f.poc_url:
                typer.echo(f"                poc: {f.poc_url}")
