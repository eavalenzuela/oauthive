"""HTML report renderer.

Self-contained jinja2 template. No external assets; styles are inlined so
the report stays portable.
"""

from __future__ import annotations

import json

from jinja2 import Environment, select_autoescape

from .redact import redact
from .schema import Report

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
STATUS_ORDER = ["fail", "error", "pass", "skipped"]

_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>oauthive report &mdash; {{ metadata.tenant_id }}</title>
<style>
  :root {
    --bg: #0f1115; --panel: #181b21; --fg: #e6e6e6; --muted: #8a8f98;
    --border: #2a2e36;
    --critical: #ff4d57; --high: #ff8a3d; --medium: #f1c21b;
    --low: #4fc3f7; --info: #8a8f98;
    --pass: #2fbf71; --fail: #ff4d57; --error: #ff8a3d; --skipped: #8a8f98;
  }
  body { background: var(--bg); color: var(--fg); font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 24px 0 8px; }
  .meta { color: var(--muted); margin-bottom: 16px; font-size: 13px; }
  .summary { display: flex; gap: 8px; flex-wrap: wrap; margin: 16px 0 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; min-width: 96px; }
  .card .n { font-size: 22px; font-weight: 600; }
  .card.critical .n, .sev.critical { color: var(--critical); }
  .card.high .n, .sev.high { color: var(--high); }
  .card.medium .n, .sev.medium { color: var(--medium); }
  .card.low .n, .sev.low { color: var(--low); }
  .card.info .n, .sev.info { color: var(--info); }
  .check { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; margin-bottom: 12px; }
  .status { display: inline-block; padding: 1px 7px; border-radius: 3px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }
  .status.pass { background: rgba(47, 191, 113, 0.18); color: var(--pass); }
  .status.fail { background: rgba(255, 77, 87, 0.18); color: var(--fail); }
  .status.error { background: rgba(255, 138, 61, 0.18); color: var(--error); }
  .status.skipped { background: rgba(138, 143, 152, 0.18); color: var(--skipped); }
  .finding { border-left: 3px solid var(--border); padding: 8px 12px; margin: 8px 0; background: rgba(255,255,255,0.02); }
  .finding.critical { border-color: var(--critical); }
  .finding.high { border-color: var(--high); }
  .finding.medium { border-color: var(--medium); }
  .finding.low { border-color: var(--low); }
  .finding.info { border-color: var(--info); }
  .sev { font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }
  .spec { color: var(--muted); font-size: 12px; }
  details > summary { cursor: pointer; color: var(--muted); margin-top: 4px; font-size: 12px; }
  pre { background: #0c0e12; border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; overflow-x: auto; font-size: 12px; }
  a { color: #6ea8fe; }
  a:hover { text-decoration: underline; }
  code { font: 12px/1.4 ui-monospace, monospace; }
  .banner { background: rgba(255, 138, 61, 0.12); border: 1px solid var(--high); color: var(--high); padding: 10px 14px; border-radius: 6px; margin: 12px 0; }
</style>
</head>
<body>
  <h1>oauthive report</h1>
  <div class="meta">
    tenant: <code>{{ metadata.tenant_id }}</code>
    &middot; issuer: <code>{{ metadata.target_issuer or "-" }}</code>
    &middot; started: {{ metadata.started_at }}
    &middot; duration: {{ (metadata.finished_at - metadata.started_at).total_seconds() | round(2) }}s
    &middot; tool: <code>oauthive {{ metadata.tool_version }}</code>
    {% if metadata.allow_public_provider %}
    &middot; <span class="sev high">public-provider override</span>: {{ metadata.allow_public_reason or "(no reason)" }}
    {% endif %}
  </div>

  {% if metadata.no_cleanup_banner %}
  <div class="banner">LIVE TOKENS RETAINED &mdash; run <code>oauthive cleanup {{ metadata.tenant_id }}</code> when done.</div>
  {% endif %}

  <div class="summary">
    {% for sev in severity_order %}
    <div class="card {{ sev }}">
      <div class="n">{{ counts[sev] or 0 }}</div>
      <div>{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <h2>Checks</h2>
  {% for check in checks_sorted %}
  <div class="check" id="check-{{ check.id }}">
    <div>
      <span class="status {{ check.status }}">{{ check.status }}</span>
      <strong>{{ check.id }}</strong> &mdash; {{ check.name }}
      <span class="spec">{{ check.duration_s | round(2) }}s</span>
    </div>
    {% if check.error %}<div class="finding high"><b>error:</b> <code>{{ check.error }}</code></div>{% endif %}
    {% if check.skip_reason %}<div class="finding info"><b>skipped:</b> <code>{{ check.skip_reason }}</code></div>{% endif %}

    {% for f in check.findings %}
    <div class="finding {{ f.severity }}">
      <div>
        <span class="sev {{ f.severity }}">{{ f.severity }}</span>
        <strong>{{ f.title }}</strong>
        <span class="spec">({{ f.id }}, confidence={{ f.confidence }})</span>
      </div>
      <div>{{ f.description }}</div>
      <div class="spec">spec: {{ f.spec_ref }}</div>
      {% if f.poc_url %}<div>PoC: <a href="{{ f.poc_url }}" target="_blank" rel="noreferrer noopener">{{ f.poc_url }}</a></div>{% endif %}
      <div><b>Remediation:</b> {{ f.remediation }}</div>
      {% if f.evidence %}
      <details><summary>evidence (redacted)</summary>
        <pre>{{ f.evidence_json }}</pre>
      </details>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endfor %}
</body>
</html>
"""

_env = Environment(autoescape=select_autoescape(["html"]))
_tpl = _env.from_string(_TEMPLATE)


def _sort_key_for_check(c) -> tuple[int, int, str]:
    try:
        sidx = STATUS_ORDER.index(c.status)
    except ValueError:
        sidx = len(STATUS_ORDER)
    worst_sev = 5
    for f in c.findings:
        try:
            worst_sev = min(worst_sev, SEVERITY_ORDER.index(f.severity))
        except ValueError:
            pass
    return (sidx, worst_sev, c.id)


def render(report: Report, *, no_cleanup_banner: bool = False) -> str:
    checks_sorted = sorted(report.checks, key=_sort_key_for_check)

    # Build rendering view: redact + JSON-encode evidence per finding.
    class _F:
        def __init__(self, f):
            self.__dict__.update(f.model_dump())
            self.evidence_json = json.dumps(redact(f.evidence), indent=2, default=str)

    class _C:
        def __init__(self, c):
            self.__dict__.update(c.model_dump())
            self.findings = [_F(f) for f in c.findings]

    return _tpl.render(
        metadata={
            **report.metadata.model_dump(),
            "no_cleanup_banner": no_cleanup_banner,
        },
        counts=report.severity_counts(),
        severity_order=SEVERITY_ORDER,
        checks_sorted=[_C(c) for c in checks_sorted],
    )
