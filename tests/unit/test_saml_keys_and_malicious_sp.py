"""Tests for M14: malicious_rp SAML role + saml_keys + vuln-sp files."""

from __future__ import annotations

import base64
import json
import socket

import httpx
import pytest

from oauthive.fixture import fixture_dir
from oauthive.malicious_rp import MaliciousRP
from oauthive.malicious_rp.saml_keys import (
    SAMLKeyPaths,
    build_sp_metadata,
    cert_b64,
    ensure_saml_keys,
)
from oauthive.malicious_rp.certs import CertError
from oauthive.saml.metadata import parse_metadata


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------- saml_keys ----------


def test_ensure_saml_keys_refuses_without_confirm(tmp_path):
    paths = SAMLKeyPaths(key=tmp_path / "sp.key", cert=tmp_path / "sp.crt")
    with pytest.raises(CertError, match="refused"):
        ensure_saml_keys(paths)


def test_ensure_saml_keys_generates_when_confirmed(tmp_path):
    paths = SAMLKeyPaths(key=tmp_path / "sp.key", cert=tmp_path / "sp.crt")
    out = ensure_saml_keys(paths, confirm=lambda _: True)
    assert out.exist()
    # Files are 0600
    assert out.cert.stat().st_mode & 0o077 == 0
    assert out.key.stat().st_mode & 0o077 == 0


def test_ensure_saml_keys_is_idempotent(tmp_path):
    paths = SAMLKeyPaths(key=tmp_path / "sp.key", cert=tmp_path / "sp.crt")
    ensure_saml_keys(paths, confirm=lambda _: True)
    # No confirm needed the second time because files exist.
    out = ensure_saml_keys(paths)
    assert out.exist()


def test_cert_b64_strips_pem_markers(tmp_path):
    paths = SAMLKeyPaths(key=tmp_path / "sp.key", cert=tmp_path / "sp.crt")
    ensure_saml_keys(paths, confirm=lambda _: True)
    b64 = cert_b64(paths)
    assert "BEGIN" not in b64 and "END" not in b64
    # Round-trip: base64 decodes to a DER cert (starts with 0x30, 0x82).
    der = base64.b64decode(b64)
    assert der[:2] == b"\x30\x82"


def test_build_sp_metadata_parses_back_as_sp_role(tmp_path):
    paths = SAMLKeyPaths(key=tmp_path / "sp.key", cert=tmp_path / "sp.crt")
    ensure_saml_keys(paths, confirm=lambda _: True)
    xml = build_sp_metadata(
        paths,
        entity_id="https://evil.example.test/sp",
        acs_url="https://127.0.0.1:8443/saml/acs",
        sls_url="https://127.0.0.1:8443/saml/sls",
    )
    md = parse_metadata(xml)
    assert md.entity_id == "https://evil.example.test/sp"
    assert md.role.startswith("sp")
    assert md.want_assertions_signed is True
    assert any(s.location.endswith("/saml/acs") for s in md.acs_services)
    assert any(s.location.endswith("/saml/sls") for s in md.slo_services)
    assert len(md.signing_certs()) == 1


# ---------- malicious_rp SAML routes ----------


async def test_malicious_rp_saml_metadata_served():
    port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=port) as rp:
        rp.set_sp_metadata(b"<md:EntityDescriptor/>")
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{rp.base_url}/saml/metadata")
        assert r.status_code == 200
        assert b"<md:EntityDescriptor/>" in r.content
        assert "samlmetadata+xml" in r.headers.get("content-type", "")


async def test_malicious_rp_saml_metadata_404_when_unset():
    port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=port) as rp:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{rp.base_url}/saml/metadata")
        assert r.status_code == 404


SIGNED_RESPONSE = b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_r" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.test</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="ok"/></samlp:Status>
  <saml:Assertion ID="_a" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.test</saml:Issuer>
    <saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"""


async def test_malicious_rp_saml_acs_captures_posted_response():
    port = _free_port()
    b64 = base64.b64encode(SIGNED_RESPONSE).decode()
    async with MaliciousRP(host="127.0.0.1", port=port) as rp:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.post(
                f"{rp.base_url}/saml/acs",
                data={"SAMLResponse": b64, "RelayState": "rs1"},
            )
        assert r.status_code == 200
    caps = rp.captures()
    assert len(caps) == 1
    cap = caps[0]
    assert cap.path == "/saml/acs"
    assert "issuer=https://idp.example.test" in cap.body
    assert "assertions=1" in cap.body


async def test_malicious_rp_saml_sls_captures_request():
    port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=port) as rp:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{rp.base_url}/saml/sls?SAMLRequest=x&RelayState=y")
        assert r.status_code == 200
    caps = rp.captures()
    assert len(caps) == 1
    assert caps[0].path == "/saml/sls"
    assert caps[0].query["SAMLRequest"] == ["x"]


# ---------- vuln-sp shipped files ----------


def test_vuln_sp_dockerfile_present():
    p = fixture_dir() / "vuln-sp" / "Dockerfile"
    assert p.is_file()
    content = p.read_text()
    assert "FROM python:3.12-slim" in content
    assert "CMD" in content and "uvicorn" in content


def test_vuln_sp_app_present_and_documents_vulns():
    p = fixture_dir() / "vuln-sp" / "app.py"
    assert p.is_file()
    content = p.read_text()
    # Intent is declared upfront.
    assert "intentionally" in content.lower() or "vulnerable" in content.lower()
    # It exposes /acs.
    assert "/acs" in content


def test_vuln_sp_requirements():
    p = fixture_dir() / "vuln-sp" / "requirements.txt"
    assert p.is_file()
    txt = p.read_text()
    assert "starlette" in txt
    assert "uvicorn" in txt


def test_docker_compose_registers_vuln_sp():
    compose = (fixture_dir() / "docker-compose.yml").read_text()
    assert "vuln-sp:" in compose
    assert "build: ./vuln-sp" in compose


def test_realm_registers_saml_client_for_vuln_sp():
    data = json.loads((fixture_dir() / "keycloak" / "realm-export.json").read_text())
    saml_clients = [c for c in data["clients"] if c.get("protocol") == "saml"]
    assert saml_clients, "no SAML clients registered in realm"
    vuln = next(
        c for c in saml_clients if c["clientId"] == "http://vuln-sp.oauthive.test/saml/sp"
    )
    # Deliberately permissive signing posture.
    assert vuln["attributes"]["saml.client.signature"] == "false"
    assert vuln["attributes"]["saml.server.signature"] == "false"


# ---------- fixture module constants ----------


def test_fixture_exposes_saml_constants():
    from oauthive import fixture as fx

    assert fx.SAML_METADATA_URL.endswith("/protocol/saml/descriptor")
    assert fx.VULN_SP_BASE == "http://127.0.0.1:8081"
    assert fx.EXPECTED_SAML_FINDING_IDS  # non-empty
