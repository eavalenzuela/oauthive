import stat


from oauthive.session import AuthSession


def test_from_token_response_parses_extra(monkeypatch):
    data = {
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "idt",
        "token_type": "Bearer",
        "scope": "openid email",
        "expires_in": 3600,
        "iss": "https://idp.example.com",
    }
    s = AuthSession.from_token_response("acme-dev", data)
    assert s.access_token == "at"
    assert s.refresh_token == "rt"
    assert s.id_token == "idt"
    assert s.scope == "openid email"
    assert s.expires_at is not None
    assert s.extra == {"iss": "https://idp.example.com"}


def test_from_token_response_missing_expires_in():
    s = AuthSession.from_token_response("t", {"access_token": "at"})
    assert s.expires_at is None
    assert s.is_expired() is False


def test_is_expired_respects_leeway():
    import time as _time

    s = AuthSession(tenant_id="t", access_token="at", expires_at=_time.time() + 10)
    assert s.is_expired(leeway_s=30) is True
    assert s.is_expired(leeway_s=0) is False


def test_save_and_load_roundtrip(tmp_path):
    s = AuthSession(tenant_id="acme-dev", access_token="at", refresh_token="rt", scope="openid")
    s.save(tmp_path)
    p = tmp_path / "acme-dev.json"
    assert p.exists()
    mode = p.stat().st_mode
    assert mode & stat.S_IRWXG == 0
    assert mode & stat.S_IRWXO == 0

    loaded = AuthSession.load("acme-dev", tmp_path)
    assert loaded is not None
    assert loaded.access_token == "at"
    assert loaded.refresh_token == "rt"
    assert loaded.scope == "openid"


def test_load_missing_returns_none(tmp_path):
    assert AuthSession.load("no-such", tmp_path) is None


def test_delete(tmp_path):
    s = AuthSession(tenant_id="acme-dev", access_token="at")
    s.save(tmp_path)
    assert AuthSession.delete("acme-dev", tmp_path) is True
    assert AuthSession.delete("acme-dev", tmp_path) is False


def test_redacted_hides_bulk():
    s = AuthSession(
        tenant_id="t",
        access_token="abcdefghijklmnop",
        refresh_token="12345678901234567890",
    )
    r = s.redacted()
    assert r["access_token"] == "abcdef...mnop"
    assert r["refresh_token"] == "123456...7890"
    assert "t" == r["tenant_id"]


def test_redacted_short_value():
    s = AuthSession(tenant_id="t", access_token="short")
    assert s.redacted()["access_token"] == "***"
