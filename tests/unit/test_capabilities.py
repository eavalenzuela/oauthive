from oauthive.capabilities import CapabilitiesReport, derive_from_discovery
from oauthive.discovery import DiscoveryDoc


def _doc(**overrides):
    base = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
    }
    base.update(overrides)
    return DiscoveryDoc.model_validate(base)


def test_empty_doc_gives_minimal_caps():
    caps = derive_from_discovery(_doc())
    assert caps.present is True
    assert caps.pkce_supported is False
    assert caps.dpop_supported is False
    assert caps.par_supported is False
    assert caps.dynamic_registration is False


def test_pkce_inferred_from_methods():
    caps = derive_from_discovery(_doc(code_challenge_methods_supported=["S256", "plain"]))
    assert caps.pkce_supported is True
    assert caps.pkce_methods == ["S256", "plain"]


def test_dpop_inferred():
    caps = derive_from_discovery(_doc(dpop_signing_alg_values_supported=["ES256"]))
    assert caps.dpop_supported is True


def test_registration_endpoint_sets_dynamic_registration():
    caps = derive_from_discovery(_doc(registration_endpoint="https://idp.example.com/register"))
    assert caps.dynamic_registration is True


def test_capability_tags_include_refresh_token():
    caps_report = CapabilitiesReport(oidc=derive_from_discovery(
        _doc(grant_types_supported=["authorization_code", "refresh_token"])
    ))
    assert "oidc" in caps_report.capability_tags()
    assert "refresh_token" in caps_report.capability_tags()


def test_capability_tags_pkce_dpop():
    caps_report = CapabilitiesReport(oidc=derive_from_discovery(
        _doc(
            code_challenge_methods_supported=["S256"],
            dpop_signing_alg_values_supported=["ES256"],
        )
    ))
    tags = caps_report.capability_tags()
    assert {"oidc", "pkce", "dpop"} <= tags
    assert "saml" not in tags
