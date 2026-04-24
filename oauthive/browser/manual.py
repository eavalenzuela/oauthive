"""Manual driver: print URL, read callback from stdin.

Useful for interactive dev when Playwright isn't installed (or isn't
appropriate because 2FA / device-bound logins refuse headless browsers).
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from .base import AuthResult, BrowserDriver, BrowserError


@dataclass
class ManualDriver(BrowserDriver):
    input_stream: object = None  # override for tests; defaults to sys.stdin
    output_stream: object = None  # override for tests; defaults to sys.stderr

    async def authorize(self, url: str, *, expected_redirect_uri: str) -> AuthResult:
        out = self.output_stream or sys.stderr
        inp = self.input_stream or sys.stdin
        print("\n[oauthive] manual-driver: paste the callback URL after logging in.", file=out)
        print(f"  auth URL: {url}", file=out)
        print(f"  expected redirect_uri prefix: {expected_redirect_uri}", file=out)
        print("  callback URL> ", end="", file=out, flush=True)

        loop = asyncio.get_running_loop()
        line = await loop.run_in_executor(None, inp.readline)
        if not line:
            raise BrowserError("manual driver: empty input (EOF)")
        return parse_callback(line.strip())


def parse_callback(callback_url: str) -> AuthResult:
    try:
        parts = urlparse(callback_url)
    except ValueError as e:
        raise BrowserError(f"could not parse callback URL: {e}") from e

    q = parse_qs(parts.query)
    # Hybrid / implicit flows put params in the fragment.
    frag = parse_qs(parts.fragment)
    merged = {**q, **frag}
    one = {k: v[0] for k, v in merged.items() if v}

    return AuthResult(
        callback_url=callback_url,
        code=one.get("code"),
        state=one.get("state"),
        id_token=one.get("id_token"),
        error=one.get("error"),
        error_description=one.get("error_description"),
    )
