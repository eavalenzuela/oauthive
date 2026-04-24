"""TOML config loader.

Matches the [discovery]/[client]/[saml]/[browser]/[malicious_rp]/[runner]/[rate_limit]
schema in PLAN.md. String values starting with '$' are looked up in os.environ.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class DiscoveryCfg(BaseModel):
    url: str


class ClientCfg(BaseModel):
    client_id: str
    client_secret: str | None = None
    redirect_uri: str
    mtls_cert: str | None = None
    mtls_key: str | None = None


class SAMLCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metadata_url: str | None = None
    metadata_file: str | None = None
    sp_entity_id: str
    acs_url: str
    sls_url: str | None = None
    sign_authn_requests: bool = True
    sp_signing_key: str | None = None
    sp_signing_cert: str | None = None


class BrowserCredentials(BaseModel):
    username: str | None = None
    password: str | None = None
    totp_secret: str | None = None


class BrowserCfg(BaseModel):
    mode: Literal["refresh", "manual", "playwright"] = "refresh"
    headless: bool = True
    credentials: BrowserCredentials = Field(default_factory=BrowserCredentials)


class MaliciousRPCfg(BaseModel):
    listen: str = "https://127.0.0.1:8443"
    cert: str | None = None
    key: str | None = None


class RunnerCfg(BaseModel):
    session_mode: Literal["isolated", "fast"] = "isolated"
    concurrency: int = 1
    per_check_timeout_s: float = 30.0


class ChecksCfg(BaseModel):
    enabled: list[str] = Field(default_factory=lambda: ["all"])
    disabled: list[str] = Field(default_factory=list)


class RateLimitCfg(BaseModel):
    token_endpoint_rps: float = 1.0
    auth_endpoint_rps: float = 2.0


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    discovery: DiscoveryCfg | None = None
    client: dict[str, ClientCfg] = Field(default_factory=dict)
    saml: SAMLCfg | None = None
    browser: BrowserCfg = Field(default_factory=BrowserCfg)
    malicious_rp: MaliciousRPCfg = Field(default_factory=MaliciousRPCfg)
    runner: RunnerCfg = Field(default_factory=RunnerCfg)
    checks: ChecksCfg = Field(default_factory=ChecksCfg)
    rate_limit: RateLimitCfg = Field(default_factory=RateLimitCfg)


class ConfigError(RuntimeError):
    pass


def _interpolate_env(value: Any) -> Any:
    """Recursively replace '$VAR' leaf strings with os.environ[VAR].

    Only exact '$VAR' (no surrounding text) is interpolated; this keeps URLs
    and literal strings safe. Missing env vars raise ConfigError.
    """
    if isinstance(value, str) and value.startswith("$") and len(value) > 1:
        var = value[1:]
        if var not in os.environ:
            raise ConfigError(f"config references ${var} but env var is not set")
        return os.environ[var]
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def load(path: str | Path) -> Config:
    p = Path(path)
    try:
        raw = tomllib.loads(p.read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {p}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"config file is not valid TOML: {e}") from e

    interpolated = _interpolate_env(raw)
    try:
        return Config.model_validate(interpolated)
    except Exception as e:
        raise ConfigError(f"config failed validation: {e}") from e
