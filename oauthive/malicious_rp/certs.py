"""Self-signed cert handling for the malicious RP.

Per PLAN.md: never auto-generate silently. The operator either supplies
cert/key paths explicitly, or approves generation via a prompt (which this
module reads through an injectable confirm callable so tests and the CLI can
wire it however they like).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertError(RuntimeError):
    pass


@dataclass
class CertPaths:
    cert: Path
    key: Path

    def exist(self) -> bool:
        return self.cert.exists() and self.key.exists()


def default_cert_paths(base: Path | None = None) -> CertPaths:
    base = base or Path.home() / ".oauthive" / "certs"
    return CertPaths(cert=base / "rp.pem", key=base / "rp.key")


def ensure_cert(
    paths: CertPaths,
    *,
    hosts: list[str] | None = None,
    confirm: Callable[[str], bool] | None = None,
) -> CertPaths:
    """Return a usable CertPaths, generating if necessary (with confirmation).

    hosts: subjects to include in the SAN. Defaults to ["localhost", "127.0.0.1", "::1"].

    confirm: callable invoked when generation is needed. It receives a prompt
    string and returns True to proceed, False to refuse. If None, generation
    is refused: the operator must supply cert/key or explicitly approve via
    a wrapper that passes confirm=lambda _p: True.
    """
    if paths.exist():
        return paths

    hosts = hosts or ["localhost", "127.0.0.1", "::1"]
    prompt = (
        f"[oauthive] Generate self-signed malicious-RP cert at {paths.cert} "
        f"(SAN={hosts})? You will need to trust it in your browser / OS once."
    )
    if confirm is None or not confirm(prompt):
        raise CertError(
            "refused to generate cert without explicit confirmation. "
            "Pre-create cert/key or pass a confirm callable."
        )

    _generate(paths, hosts)
    return paths


def _generate(paths: CertPaths, hosts: list[str]) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    sans: list[x509.GeneralName] = []
    for h in hosts:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    paths.cert.parent.mkdir(parents=True, exist_ok=True)
    paths.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths.key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths.cert.chmod(0o600)
    paths.key.chmod(0o600)
