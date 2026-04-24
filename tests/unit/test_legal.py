import pytest

from oauthive.legal import LegalGuardError, assert_permitted, host_is_public_provider


def test_denylist_exact_hosts():
    assert host_is_public_provider("accounts.google.com")
    assert host_is_public_provider("login.microsoftonline.com")
    assert not host_is_public_provider("idp.example.com")


def test_denylist_suffixes():
    assert host_is_public_provider("acme.okta.com")
    assert host_is_public_provider("dev-xyz.us.auth0.com")
    assert not host_is_public_provider("acme.okta.internal")


def test_requires_tenant_id():
    with pytest.raises(LegalGuardError, match="--i-own-this-tenant"):
        assert_permitted("https://idp.example.com/.well-known/openid-configuration", None)


def test_blocks_public_provider_without_override():
    with pytest.raises(LegalGuardError, match="public provider"):
        assert_permitted("https://accounts.google.com/.well-known/openid-configuration", "my-tenant")


def test_public_provider_override_requires_reason():
    with pytest.raises(LegalGuardError, match="--reason"):
        assert_permitted(
            "https://accounts.google.com/.well-known/openid-configuration",
            "my-tenant",
            allow_public_provider=True,
        )


def test_public_provider_override_with_reason():
    assert_permitted(
        "https://accounts.google.com/.well-known/openid-configuration",
        "my-tenant",
        allow_public_provider=True,
        reason="dedicated workspace owned by my org",
    )


def test_private_tenant_passes():
    assert_permitted("https://idp.example.com/x", "my-tenant")
