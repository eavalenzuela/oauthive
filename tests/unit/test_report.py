import json

import pytest

from oauthive.report import html as html_report
from oauthive.report import markdown as md_report
from oauthive.report.redact import redact
from oauthive.report.schema import (
    CheckRecord,
    FindingRecord,
    Report,
    RunMetadata,
    now_utc,
)


def _sample_report() -> Report:
    now = now_utc()
    findings = [
        FindingRecord(
            id="redirect_uri.subdomain_append",
            severity="critical",
            confidence="high",
            title="Subdomain append accepted",
            description="Host tacked onto attacker domain accepted.",
            spec_ref="RFC 6749 sec 3.1.2",
            remediation="Exact-match redirect_uri.",
            poc_url="https://idp.example.test/authorize?redirect_uri=evil",
            evidence={
                "status_code": 302,
                "location": "https://app.example.test.evil.example.test/cb",
                "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.aaaaaaaaaa",
            },
        ),
        FindingRecord(
            id="pkce.not_required",
            severity="high",
            confidence="high",
            title="PKCE not required",
            description="Auth flow without code_challenge succeeded.",
            spec_ref="RFC 7636 sec 4.4.1",
            remediation="Enforce PKCE.",
            evidence={},
        ),
    ]
    return Report(
        metadata=RunMetadata(
            tenant_id="acme-dev",
            started_at=now,
            finished_at=now,
            tool_version="0.0.1",
            target_issuer="https://idp.example.test",
        ),
        checks=[
            CheckRecord(
                id="redirect_uri",
                name="redirect_uri",
                status="fail",
                duration_s=0.3,
                findings=findings[:1],
            ),
            CheckRecord(
                id="pkce",
                name="pkce",
                status="fail",
                duration_s=0.1,
                findings=findings[1:],
            ),
            CheckRecord(id="state", name="state", status="pass", duration_s=0.05),
            CheckRecord(
                id="id_token",
                name="id_token",
                status="skipped",
                duration_s=0.0,
                skip_reason="missing capabilities: ['saml']",
            ),
        ],
    )


# ---------- redact ----------


def test_redact_jwt_shape():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.aaaaaaaaaa"
    r = redact(token)
    assert r != token
    assert r.startswith("eyJhbG")
    assert "..." in r


def test_redact_by_key_name():
    out = redact({"access_token": "short", "other": "short"})
    assert out["access_token"] != "short"
    assert out["other"] == "short"  # short string, not matched by length regex


def test_redact_nested():
    out = redact({"a": [{"access_token": "long-enough-to-trigger-regex-xyz123"}]})
    assert out["a"][0]["access_token"] != "long-enough-to-trigger-regex-xyz123"


def test_redact_leaves_short_non_sensitive():
    out = redact({"status_code": 302, "error": "invalid"})
    assert out == {"status_code": 302, "error": "invalid"}


# ---------- html ----------


def test_html_summary_counts_and_structure():
    report = _sample_report()
    html = html_report.render(report)
    assert "<html" in html and "</html>" in html
    # Tenant shown
    assert "acme-dev" in html
    # Both findings rendered
    assert "redirect_uri.subdomain_append" in html
    assert "pkce.not_required" in html
    # Severity badges present
    assert "critical" in html
    assert "high" in html
    # Skipped + passed checks shown
    assert "skipped" in html
    assert "missing capabilities" in html


def test_html_redacts_jwt_in_evidence():
    report = _sample_report()
    html = html_report.render(report)
    # The raw token should NOT appear verbatim...
    raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.aaaaaaaaaa"
    assert raw not in html
    # ...but the redacted form should.
    assert "eyJhbG" in html and "..." in html


def test_html_banner_when_no_cleanup():
    report = _sample_report()
    html = html_report.render(report, no_cleanup_banner=True)
    assert "LIVE TOKENS RETAINED" in html


def test_html_no_banner_by_default():
    report = _sample_report()
    html = html_report.render(report)
    assert "LIVE TOKENS RETAINED" not in html


# ---------- markdown ----------


def test_md_contains_structure():
    report = _sample_report()
    md = md_report.render(report)
    assert md.startswith("# oauthive report")
    assert "| Severity | Count |" in md
    assert "## Checks" in md
    assert "[FAIL]" in md
    assert "[SKIPPED]" in md
    assert "redirect_uri.subdomain_append" in md


def test_md_redacts_evidence():
    report = _sample_report()
    md = md_report.render(report)
    raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.aaaaaaaaaa"
    assert raw not in md


# ---------- round-trip via findings.json ----------


def test_report_roundtrip_via_json(tmp_path):
    report = _sample_report()
    payload = json.loads(report.model_dump_json())
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(payload))

    data = json.loads(path.read_text())
    # Drop a hypothetical cleanup block (as the CLI does).
    data.pop("cleanup_report", None)
    restored = Report.model_validate(data)
    html = html_report.render(restored)
    assert "acme-dev" in html
    assert "redirect_uri.subdomain_append" in html
