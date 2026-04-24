"""Markdown report renderer.

Same content as HTML, designed to paste into a PR / issue / ticket.
"""

from __future__ import annotations

import json

from .html import SEVERITY_ORDER, STATUS_ORDER, _sort_key_for_check
from .redact import redact
from .schema import Report


def render(report: Report, *, no_cleanup_banner: bool = False) -> str:
    md = report.metadata
    out: list[str] = []
    out.append(f"# oauthive report")
    out.append("")
    out.append(f"- tenant: `{md.tenant_id}`")
    if md.target_issuer:
        out.append(f"- issuer: `{md.target_issuer}`")
    out.append(f"- started: {md.started_at}")
    out.append(
        f"- duration: {(md.finished_at - md.started_at).total_seconds():.2f}s"
    )
    out.append(f"- tool: `oauthive {md.tool_version}`")
    if md.allow_public_provider:
        out.append(
            f"- **public-provider override**: {md.allow_public_reason or '(no reason)'}"
        )
    out.append("")

    if no_cleanup_banner:
        out.append(
            f"> **LIVE TOKENS RETAINED** — run `oauthive cleanup {md.tenant_id}` when done."
        )
        out.append("")

    counts = report.severity_counts()
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for sev in SEVERITY_ORDER:
        out.append(f"| {sev} | {counts[sev]} |")
    out.append("")

    out.append("## Checks")
    out.append("")
    for check in sorted(report.checks, key=_sort_key_for_check):
        status = check.status.upper()
        out.append(f"### [{status}] `{check.id}` — {check.name} ({check.duration_s:.2f}s)")
        out.append("")
        if check.error:
            out.append(f"- **error:** `{check.error}`")
        if check.skip_reason:
            out.append(f"- **skipped:** `{check.skip_reason}`")
        if not check.findings:
            if check.status == "pass":
                out.append("_No findings._")
            out.append("")
            continue
        for f in check.findings:
            out.append(f"- **[{f.severity}]** `{f.id}` — {f.title}")
            out.append(f"  - confidence: {f.confidence}")
            out.append(f"  - spec: {f.spec_ref}")
            out.append(f"  - description: {f.description}")
            if f.poc_url:
                out.append(f"  - PoC: {f.poc_url}")
            out.append(f"  - remediation: {f.remediation}")
            if f.evidence:
                ev = json.dumps(redact(f.evidence), indent=2, default=str)
                out.append("  - evidence (redacted):")
                out.append("")
                out.append("    ```json")
                for line in ev.splitlines():
                    out.append(f"    {line}")
                out.append("    ```")
            out.append("")
        out.append("")

    return "\n".join(out).rstrip() + "\n"
