"""Tests for the fixture control module.

Does not actually run Docker. Confirms:
- the shipped files exist and parse
- the realm-export.json encodes the intentional misconfigs
- the CLI builds the expected docker compose commands
- docker-not-installed produces a friendly FixtureError
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oauthive import fixture as fx


# ---------- shipped files ----------


def test_fixture_dir_contains_compose_and_realm():
    d = fx.fixture_dir()
    assert (d / "docker-compose.yml").is_file()
    assert (d / "keycloak" / "realm-export.json").is_file()
    assert (d / "README.md").is_file()


def test_realm_export_is_valid_json():
    path = fx.fixture_dir() / "keycloak" / "realm-export.json"
    json.loads(path.read_text())


def test_realm_has_public_client_without_pkce_enforcement():
    data = json.loads((fx.fixture_dir() / "keycloak" / "realm-export.json").read_text())
    client = next(
        c for c in data["clients"] if c["clientId"] == "oauthive-public-no-pkce"
    )
    assert client["publicClient"] is True
    # Absent or empty pkce.code.challenge.method => not enforced.
    assert client.get("attributes", {}).get("pkce.code.challenge.method", "") == ""
    # Implicit flow explicitly enabled so response_type.implicit_* fire.
    assert client["implicitFlowEnabled"] is True


def test_realm_has_prefix_match_redirect_client():
    data = json.loads((fx.fixture_dir() / "keycloak" / "realm-export.json").read_text())
    client = next(
        c for c in data["clients"] if c["clientId"] == "oauthive-prefix-redirect"
    )
    assert any(uri.endswith("/*") for uri in client["redirectUris"])


def test_realm_has_control_client():
    data = json.loads((fx.fixture_dir() / "keycloak" / "realm-export.json").read_text())
    client = next(c for c in data["clients"] if c["clientId"] == "oauthive-confidential")
    assert client["publicClient"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"


def test_realm_disables_refresh_rotation():
    data = json.loads((fx.fixture_dir() / "keycloak" / "realm-export.json").read_text())
    # revokeRefreshToken false means "don't require single-use rotation"
    assert data.get("revokeRefreshToken") is False


# ---------- command builders ----------


def test_up_cmd_shape(monkeypatch):
    monkeypatch.setattr(fx.shutil, "which", lambda _n: "/usr/bin/docker")
    cmd = fx.up_cmd()
    assert cmd.argv[:3] == ["docker", "compose", "up"]
    assert "-d" in cmd.argv
    assert cmd.cwd == fx.fixture_dir()


def test_down_cmd_shape(monkeypatch):
    monkeypatch.setattr(fx.shutil, "which", lambda _n: "/usr/bin/docker")
    cmd = fx.down_cmd(volumes=True)
    assert cmd.argv[:3] == ["docker", "compose", "down"]
    assert "-v" in cmd.argv


def test_down_cmd_keep_volumes(monkeypatch):
    monkeypatch.setattr(fx.shutil, "which", lambda _n: "/usr/bin/docker")
    cmd = fx.down_cmd(volumes=False)
    assert "-v" not in cmd.argv


def test_up_cmd_without_docker(monkeypatch):
    monkeypatch.setattr(fx.shutil, "which", lambda _n: None)
    with pytest.raises(fx.FixtureError, match="docker"):
        fx.up_cmd()


# ---------- expected findings ----------


def test_expected_finding_ids_nonempty():
    assert len(fx.EXPECTED_FINDING_IDS) >= 2


def test_discovery_url_matches_compose_host():
    assert fx.DISCOVERY_URL.startswith("http://127.0.0.1:8080/")
    assert fx.REALM in fx.DISCOVERY_URL
