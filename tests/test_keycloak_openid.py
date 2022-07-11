"""Test module for KeycloakOpenID."""
from unittest import mock

import pytest

from keycloak.authorization import Authorization
from keycloak.connection import ConnectionManager
from keycloak.exceptions import KeycloakDeprecationError, KeycloakRPTNotFound
from keycloak.keycloak_admin import KeycloakAdmin
from keycloak.keycloak_openid import KeycloakOpenID


def test_keycloak_openid_init(env):
    """Test KeycloakOpenId's init method."""
    oid = KeycloakOpenID(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        realm_name="master",
        client_id="admin-cli",
    )

    assert oid.client_id == "admin-cli"
    assert oid.client_secret_key is None
    assert oid.realm_name == "master"
    assert isinstance(oid.connection, ConnectionManager)
    assert isinstance(oid.authorization, Authorization)


def test_well_known(oid: KeycloakOpenID):
    """Test the well_known method."""
    res = oid.well_known()
    assert res is not None
    assert res != dict()
    for key in [
        "acr_values_supported",
        "authorization_encryption_alg_values_supported",
        "authorization_encryption_enc_values_supported",
        "authorization_endpoint",
        "authorization_signing_alg_values_supported",
        "backchannel_authentication_endpoint",
        "backchannel_authentication_request_signing_alg_values_supported",
        "backchannel_logout_session_supported",
        "backchannel_logout_supported",
        "backchannel_token_delivery_modes_supported",
        "check_session_iframe",
        "claim_types_supported",
        "claims_parameter_supported",
        "claims_supported",
        "code_challenge_methods_supported",
        "device_authorization_endpoint",
        "end_session_endpoint",
        "frontchannel_logout_session_supported",
        "frontchannel_logout_supported",
        "grant_types_supported",
        "id_token_encryption_alg_values_supported",
        "id_token_encryption_enc_values_supported",
        "id_token_signing_alg_values_supported",
        "introspection_endpoint",
        "introspection_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "issuer",
        "jwks_uri",
        "mtls_endpoint_aliases",
        "pushed_authorization_request_endpoint",
        "registration_endpoint",
        "request_object_encryption_alg_values_supported",
        "request_object_encryption_enc_values_supported",
        "request_object_signing_alg_values_supported",
        "request_parameter_supported",
        "request_uri_parameter_supported",
        "require_pushed_authorization_requests",
        "require_request_uri_registration",
        "response_modes_supported",
        "response_types_supported",
        "revocation_endpoint",
        "revocation_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
        "scopes_supported",
        "subject_types_supported",
        "tls_client_certificate_bound_access_tokens",
        "token_endpoint",
        "token_endpoint_auth_methods_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "userinfo_encryption_alg_values_supported",
        "userinfo_encryption_enc_values_supported",
        "userinfo_endpoint",
        "userinfo_signing_alg_values_supported",
    ]:
        assert key in res


def test_auth_url(env, oid: KeycloakOpenID):
    """Test the auth_url method."""
    res = oid.auth_url(redirect_uri="http://test.test/*")
    assert (
        res
        == f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}/realms/{oid.realm_name}"
        + f"/protocol/openid-connect/auth?client_id={oid.client_id}&response_type=code"
        + "&redirect_uri=http://test.test/*"
    )


def test_token(oid_with_credentials: tuple[KeycloakOpenID, str, str]):
    """Test the token method."""
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with dummy totp
    token = oid.token(username=username, password=password, totp="123456")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with extra param
    token = oid.token(username=username, password=password, extra_param="foo")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }


def test_exchange_token(
    oid_with_credentials: tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin
):
    """Test the exchange token method."""
    # Verify existing user
    oid, username, password = oid_with_credentials

    # Allow impersonation
    admin.realm_name = oid.realm_name
    admin.assign_client_role(
        user_id=admin.get_user_id(username=username),
        client_id=admin.get_client_id(client_name="realm-management"),
        roles=[
            admin.get_client_role(
                client_id=admin.get_client_id(client_name="realm-management"),
                role_name="impersonation",
            )
        ],
    )

    token = oid.token(username=username, password=password)
    assert oid.userinfo(token=token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": False,
        "preferred_username": username,
        "sub": mock.ANY,
    }

    # Exchange token with the new user
    new_token = oid.exchange_token(
        token=token["access_token"],
        client_id=oid.client_id,
        audience=oid.client_id,
        subject=username,
    )
    assert oid.userinfo(token=new_token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": False,
        "preferred_username": username,
        "sub": mock.ANY,
    }
    assert token != new_token


def test_certs(oid: KeycloakOpenID):
    """Test certificates."""
    assert len(oid.certs()["keys"]) == 2


def test_public_key(oid: KeycloakOpenID):
    """Test public key."""
    assert oid.public_key() is not None


def test_entitlement(
    oid_with_credentials_authz: tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin
):
    """Test entitlement."""
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)
    resource_server_id = admin.get_client_authz_resources(
        client_id=admin.get_client_id(oid.client_id)
    )[0]["_id"]

    with pytest.raises(KeycloakDeprecationError):
        oid.entitlement(token=token["access_token"], resource_server_id=resource_server_id)


def test_introspect(oid_with_credentials: tuple[KeycloakOpenID, str, str]):
    """Test introspect."""
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)

    assert oid.introspect(token=token["access_token"])["active"]
    assert oid.introspect(
        token=token["access_token"], rpt="some", token_type_hint="requesting_party_token"
    ) == {"active": False}

    with pytest.raises(KeycloakRPTNotFound):
        oid.introspect(token=token["access_token"], token_type_hint="requesting_party_token")


def test_decode_token(oid_with_credentials: tuple[KeycloakOpenID, str, str]):
    """Test decode token."""
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)

    assert (
        oid.decode_token(
            token=token["access_token"],
            key="-----BEGIN PUBLIC KEY-----\n" + oid.public_key() + "\n-----END PUBLIC KEY-----",
            options={"verify_aud": False},
        )["preferred_username"]
        == username
    )
