from oauthive.checks.redirect_uri import candidates_for


def test_candidates_include_expected_classes():
    got = {c.id for c in candidates_for("https://app.example.test/cb")}
    expected = {
        "exact",
        "fragment_confusion",
        "path_traversal",
        "userinfo_injection",
        "subdomain_append",
        "foreign_host",
        "scheme_downgrade",
        "path_suffix",
        "query_append",
    }
    assert expected <= got


def test_localhost_gets_port_wildcard_candidate():
    got = {c.id for c in candidates_for("http://127.0.0.1:8443/cb")}
    assert "localhost_port_wildcard" in got


def test_non_localhost_has_no_port_wildcard_candidate():
    got = {c.id for c in candidates_for("https://app.example.test/cb")}
    assert "localhost_port_wildcard" not in got


def test_exact_candidate_preserved_verbatim():
    cands = {c.id: c.uri for c in candidates_for("https://app.example.test/cb")}
    assert cands["exact"] == "https://app.example.test/cb"


def test_foreign_host_never_matches_registered_host():
    cands = {c.id: c.uri for c in candidates_for("https://app.example.test/cb")}
    assert "app.example.test" not in cands["foreign_host"].split("/")[2]


def test_scheme_downgrade_from_https_is_high_severity():
    cands = {c.id: c for c in candidates_for("https://app.example.test/cb")}
    assert cands["scheme_downgrade"].severity_if_accepted == "high"


def test_scheme_downgrade_from_http_is_info():
    cands = {c.id: c for c in candidates_for("http://app.example.test/cb")}
    assert cands["scheme_downgrade"].severity_if_accepted == "info"
