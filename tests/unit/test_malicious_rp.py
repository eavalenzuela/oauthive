
import httpx
import pytest

from oauthive.malicious_rp import MaliciousRP
from oauthive.malicious_rp.certs import CertError, CertPaths, ensure_cert


def test_ensure_cert_refuses_without_confirm(tmp_path):
    paths = CertPaths(cert=tmp_path / "c.pem", key=tmp_path / "c.key")
    with pytest.raises(CertError, match="refused"):
        ensure_cert(paths)


def test_ensure_cert_generates_when_confirmed(tmp_path):
    paths = CertPaths(cert=tmp_path / "c.pem", key=tmp_path / "c.key")
    out = ensure_cert(paths, confirm=lambda _: True)
    assert out.cert.exists() and out.key.exists()
    assert out.cert.stat().st_mode & 0o077 == 0  # no group/other perms
    # Round-trip: cert is parseable.
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(out.cert.read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = [n.value for n in sans if isinstance(n, x509.DNSName)]
    assert "localhost" in dns


def test_ensure_cert_idempotent_when_both_files_present(tmp_path):
    paths = CertPaths(cert=tmp_path / "c.pem", key=tmp_path / "c.key")
    ensure_cert(paths, confirm=lambda _: True)
    # Writing an empty confirm this second time should still succeed (no gen).
    out = ensure_cert(paths)  # no confirm needed because files exist
    assert out.cert == paths.cert


async def test_malicious_rp_refuses_public_bind_by_default():
    with pytest.raises(RuntimeError, match="public host"):
        MaliciousRP(host="0.0.0.0", port=8443)


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_malicious_rp_roundtrip():
    unused_tcp_port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=unused_tcp_port) as rp:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{rp.base_url}/cb?code=abc&state=s&x=1")
            assert r.status_code == 200
            assert "oauthive malicious-rp capture" in r.text
        caps = rp.captures()
        assert len(caps) == 1
        cap = caps[0]
        assert cap.path == "/cb"
        assert cap.query["code"] == ["abc"]
        assert cap.query["state"] == ["s"]


async def test_malicious_rp_jwks_serving():
    unused_tcp_port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=unused_tcp_port) as rp:
        rp.set_jwks({"keys": [{"kty": "RSA", "kid": "attacker", "n": "AA", "e": "AQAB"}]})
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{rp.base_url}/jwks.json")
            assert r.status_code == 200
            assert r.json()["keys"][0]["kid"] == "attacker"


async def test_malicious_rp_captures_endpoint():
    unused_tcp_port = _free_port()
    async with MaliciousRP(host="127.0.0.1", port=unused_tcp_port) as rp:
        async with httpx.AsyncClient(timeout=3.0) as c:
            await c.get(f"{rp.base_url}/cb?code=x")
            r = await c.get(f"{rp.base_url}/captures")
            data = r.json()
            # /cb call + the /captures call itself (which is also captured? no,
            # /captures isn't wired to _capture). Confirm just the /cb entry.
            assert any(e["path"] == "/cb" for e in data)
