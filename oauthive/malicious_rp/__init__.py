"""The malicious RP / SP harness.

Spins up a local HTTPS server that plays 'evil relying party' / 'evil service
provider' for the mix-up, redirect-uri confusion, JKU/X5U pivot, and
SAML-confusion checks.

- server.MaliciousRP        : the uvicorn/starlette app + lifecycle manager
- certs                     : self-signed cert handling (prompt-on-generate)
- saml_keys                 : SP signing keypair (SAML side, M14)
"""

from __future__ import annotations

from .certs import CertError, ensure_cert
from .server import CapturedRequest, MaliciousRP

__all__ = ["CapturedRequest", "CertError", "MaliciousRP", "ensure_cert"]
