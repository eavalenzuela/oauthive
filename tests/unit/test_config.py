
import pytest

from oauthive.config import ConfigError, load


def test_load_minimal(tmp_path):
    p = tmp_path / "oauthive.toml"
    p.write_text(
        """
tenant_id = "acme-dev"

[discovery]
url = "https://idp.example.com/.well-known/openid-configuration"

[client.primary]
client_id = "oauthive-test"
redirect_uri = "https://127.0.0.1:8443/cb"
"""
    )
    cfg = load(p)
    assert cfg.tenant_id == "acme-dev"
    assert cfg.client["primary"].client_id == "oauthive-test"
    assert cfg.runner.session_mode == "isolated"


def test_env_var_interpolation(tmp_path, monkeypatch):
    monkeypatch.setenv("OA_SECRET", "s3kret")
    p = tmp_path / "oauthive.toml"
    p.write_text(
        """
tenant_id = "acme-dev"

[client.primary]
client_id = "oauthive-test"
client_secret = "$OA_SECRET"
redirect_uri = "https://127.0.0.1:8443/cb"
"""
    )
    cfg = load(p)
    assert cfg.client["primary"].client_secret == "s3kret"


def test_missing_env_var_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("OA_MISSING", raising=False)
    p = tmp_path / "oauthive.toml"
    p.write_text(
        """
tenant_id = "acme-dev"

[client.primary]
client_id = "oauthive-test"
client_secret = "$OA_MISSING"
redirect_uri = "https://127.0.0.1:8443/cb"
"""
    )
    with pytest.raises(ConfigError, match="OA_MISSING"):
        load(p)


def test_missing_file_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "nope.toml")


def test_unknown_top_level_key_rejected(tmp_path):
    p = tmp_path / "oauthive.toml"
    p.write_text(
        """
tenant_id = "acme-dev"
unknown_section = "hi"
"""
    )
    with pytest.raises(ConfigError):
        load(p)
