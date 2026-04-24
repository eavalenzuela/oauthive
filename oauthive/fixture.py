"""Keycloak self-test fixture control.

Shells out to `docker compose` against the fixture dir shipped in
oauthive/fixtures/. Implementations are intentionally thin; the fixture's
identity -- which realm, which clients, what misconfigs -- lives in the
versioned data files, not here.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx


def fixture_dir() -> Path:
    return Path(__file__).parent / "fixtures"


KEYCLOAK_BASE = "http://127.0.0.1:8080"
REALM = "oauthive-dev"
DISCOVERY_URL = f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/openid-configuration"
SAML_METADATA_URL = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/saml/descriptor"
HEALTH_URL = f"{KEYCLOAK_BASE}/health/ready"
VULN_SP_BASE = "http://127.0.0.1:8081"
VULN_SP_HEALTH = f"{VULN_SP_BASE}/health"
EXPECTED_FINDING_IDS = {
    "pkce.not_required",
    "response_type.implicit_advertised",
    "response_type.implicit_token_issued",
}
EXPECTED_SAML_FINDING_IDS = {
    # Keycloak serves SAML metadata unsigned by default and without validUntil
    # in the generated descriptor.
    "saml_assertion.metadata_unsigned",
    "saml_metadata.valid_until_absent",
    # Informational pointers always fire when metadata is present.
    "saml_xsw.exercise_against_sp",
    "saml_comment.exercise_against_sp",
    "saml_xxe.exercise_against_idp",
}


class FixtureError(RuntimeError):
    pass


@dataclass
class DockerCommand:
    argv: list[str]
    cwd: Path


def _compose_cmd(action: list[str]) -> DockerCommand:
    if shutil.which("docker") is None:
        raise FixtureError(
            "docker not found on PATH. Install Docker (or Podman with `alias docker=podman`) "
            "to use the oauthive fixture."
        )
    return DockerCommand(argv=["docker", "compose", *action], cwd=fixture_dir())


def up_cmd() -> DockerCommand:
    return _compose_cmd(["up", "-d"])


def down_cmd(*, volumes: bool = True) -> DockerCommand:
    args = ["down"]
    if volumes:
        args.append("-v")
    return _compose_cmd(args)


def run(cmd: DockerCommand) -> int:
    """Run a DockerCommand synchronously, streaming output. Returns the exit code."""
    proc = subprocess.run(cmd.argv, cwd=cmd.cwd)
    return proc.returncode


async def wait_for_ready(*, timeout_s: float = 90.0, poll_s: float = 2.0) -> None:
    """Poll Keycloak's health endpoint until ready or timeout."""
    deadline = asyncio.get_running_loop().time() + timeout_s
    async with httpx.AsyncClient(timeout=5.0) as c:
        while True:
            try:
                resp = await c.get(HEALTH_URL)
                if resp.status_code == 200 and '"status": "UP"' in resp.text:
                    return
            except httpx.HTTPError:
                pass
            if asyncio.get_running_loop().time() > deadline:
                raise FixtureError(
                    f"keycloak did not become ready at {HEALTH_URL} within {timeout_s:.0f}s"
                )
            await asyncio.sleep(poll_s)
