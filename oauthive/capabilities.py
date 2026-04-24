"""Capabilities probe.

At M1, this is metadata-inference only: we look at the discovery doc and
conclude what the IdP *claims* to support. Active probing (sending a PKCE
request without a code_verifier to see what the server actually does) is added
by later milestones that need it; each such probe annotates the source of its
conclusion on the CapabilitiesReport so checks can distinguish "advertised" from
"observed".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from .discovery import DiscoveryDoc

if TYPE_CHECKING:
    from .saml.metadata import EntityDescriptor


class OIDCCapabilities(BaseModel):
    present: bool = False
    issuer: str | None = None
    pkce_supported: bool = False
    pkce_methods: list[str] = Field(default_factory=list)
    pkce_required_for_public: bool | None = None  # None = unknown without active probe
    dpop_supported: bool = False
    mtls_bound_tokens: bool = False
    par_supported: bool = False
    par_required: bool | None = None
    dynamic_registration: bool = False
    revocation_endpoint: bool = False
    introspection_endpoint: bool = False
    end_session_endpoint: bool = False
    backchannel_logout: bool = False
    supported_response_types: list[str] = Field(default_factory=list)
    supported_response_modes: list[str] = Field(default_factory=list)
    supported_grant_types: list[str] = Field(default_factory=list)
    id_token_signing_algs: list[str] = Field(default_factory=list)


class SAMLCapabilities(BaseModel):
    present: bool = False
    entity_id: str | None = None
    sso_bindings: list[str] = Field(default_factory=list)
    slo_bindings: list[str] = Field(default_factory=list)
    want_authn_requests_signed: bool | None = None
    sign_assertions: bool | None = None
    sign_responses: bool | None = None
    encrypt_assertions: bool | None = None
    nameid_formats: list[str] = Field(default_factory=list)
    signing_algs: list[str] = Field(default_factory=list)
    digest_algs: list[str] = Field(default_factory=list)
    metadata_signed: bool | None = None
    metadata_url: str | None = None


class CapabilitiesReport(BaseModel):
    oidc: OIDCCapabilities = Field(default_factory=OIDCCapabilities)
    saml: SAMLCapabilities = Field(default_factory=SAMLCapabilities)

    def capability_tags(self) -> set[str]:
        """Tags checks can require via Check.requires_capabilities."""
        tags: set[str] = set()
        if self.oidc.present:
            tags.add("oidc")
            if self.oidc.pkce_supported:
                tags.add("pkce")
            if self.oidc.dpop_supported:
                tags.add("dpop")
            if self.oidc.mtls_bound_tokens:
                tags.add("mtls")
            if self.oidc.par_supported:
                tags.add("par")
            if self.oidc.dynamic_registration:
                tags.add("dynamic_registration")
            if self.oidc.revocation_endpoint:
                tags.add("revocation")
            if self.oidc.end_session_endpoint:
                tags.add("end_session")
            if "refresh_token" in self.oidc.supported_grant_types:
                tags.add("refresh_token")
        if self.saml.present:
            tags.add("saml")
        return tags


def derive_from_saml_metadata(md: "EntityDescriptor") -> SAMLCapabilities:
    """Populate SAMLCapabilities from a parsed EntityDescriptor.

    Operates on the 'public' shape of the metadata only -- certificate
    fingerprints / algorithm lists come from later-milestone checks that
    inspect the KeyInfo and signature algs deeper.
    """
    return SAMLCapabilities(
        present=True,
        entity_id=md.entity_id,
        sso_bindings=md.sso_bindings(),
        slo_bindings=md.slo_bindings(),
        want_authn_requests_signed=md.want_authn_requests_signed,
        sign_assertions=md.want_assertions_signed,
        name_id_formats=list(md.name_id_formats),
        metadata_signed=md.metadata_signed,
    )


def derive_from_discovery(doc: DiscoveryDoc) -> OIDCCapabilities:
    """Infer OIDC capabilities from a discovery doc's advertised fields."""
    return OIDCCapabilities(
        present=True,
        issuer=str(doc.issuer),
        pkce_supported=bool(doc.code_challenge_methods_supported),
        pkce_methods=list(doc.code_challenge_methods_supported),
        dpop_supported=bool(doc.dpop_signing_alg_values_supported),
        mtls_bound_tokens=bool(doc.tls_client_certificate_bound_access_tokens),
        par_supported=doc.pushed_authorization_request_endpoint is not None,
        par_required=doc.require_pushed_authorization_requests,
        dynamic_registration=doc.registration_endpoint is not None,
        revocation_endpoint=doc.revocation_endpoint is not None,
        introspection_endpoint=doc.introspection_endpoint is not None,
        end_session_endpoint=doc.end_session_endpoint is not None,
        backchannel_logout=bool(doc.backchannel_logout_supported),
        supported_response_types=list(doc.response_types_supported),
        supported_response_modes=list(doc.response_modes_supported),
        supported_grant_types=list(doc.grant_types_supported),
        id_token_signing_algs=list(doc.id_token_signing_alg_values_supported),
    )
