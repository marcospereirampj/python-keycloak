"""Test module for KeycloakOpenID."""

from inspect import iscoroutinefunction, signature
from typing import Tuple
from unittest import mock

import jwcrypto.jwk
import jwcrypto.jws
import pytest

from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.authorization import Authorization
from keycloak.authorization.permission import Permission
from keycloak.authorization.policy import Policy
from keycloak.authorization.role import Role
from keycloak.connection import ConnectionManager
from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakAuthorizationConfigError,
    KeycloakDeprecationError,
    KeycloakInvalidTokenError,
    KeycloakPostError,
    KeycloakRPTNotFound,
)


def test_keycloak_openid_init(env):
    """Test KeycloakOpenId's init method.

    :param env: Environment fixture
    :type env: KeycloakTestEnv
    """
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
    """Test the well_known method.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
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
    """Test the auth_url method.

    :param env: Environment fixture
    :type env: KeycloakTestEnv
    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    res = oid.auth_url(redirect_uri="http://test.test/*")
    assert (
        res
        == f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}/realms/{oid.realm_name}"
        + f"/protocol/openid-connect/auth?client_id={oid.client_id}&response_type=code"
        + "&redirect_uri=http://test.test/*&scope=email&state=&nonce="
    )


def test_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test the token method.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with dummy totp
    token = oid.token(username=username, password=password, totp="123456")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with extra param
    token = oid.token(username=username, password=password, extra_param="foo")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }


def test_exchange_token(
    oid_with_credentials: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test the exchange token method.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    # Verify existing user
    oid, username, password = oid_with_credentials

    # Allow impersonation
    admin.change_current_realm(oid.realm_name)
    admin.assign_client_role(
        user_id=admin.get_user_id(username=username),
        client_id=admin.get_client_id(client_id="realm-management"),
        roles=[
            admin.get_client_role(
                client_id=admin.get_client_id(client_id="realm-management"),
                role_name="impersonation",
            ),
        ],
    )

    token = oid.token(username=username, password=password)
    assert oid.userinfo(token=token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": True,
        "family_name": "last",
        "given_name": "first",
        "name": "first last",
        "preferred_username": username,
        "sub": mock.ANY,
    }

    # Exchange token with the new user
    new_token = oid.exchange_token(
        token=token["access_token"], audience=oid.client_id, subject=username,
    )
    assert oid.userinfo(token=new_token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": True,
        "family_name": "last",
        "given_name": "first",
        "name": "first last",
        "preferred_username": username,
        "sub": mock.ANY,
    }
    assert token != new_token


def test_logout(oid_with_credentials):
    """Test logout.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials

    token = oid.token(username=username, password=password)
    assert oid.userinfo(token=token["access_token"]) != dict()
    assert oid.logout(refresh_token=token["refresh_token"]) == dict()

    with pytest.raises(KeycloakAuthenticationError):
        oid.userinfo(token=token["access_token"])


def test_certs(oid: KeycloakOpenID):
    """Test certificates.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    assert len(oid.certs()["keys"]) == 2


def test_public_key(oid: KeycloakOpenID):
    """Test public key.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    assert oid.public_key() is not None


def test_entitlement(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test entitlement.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)
    resource_server_id = admin.get_client_authz_resources(
        client_id=admin.get_client_id(oid.client_id),
    )[0]["_id"]

    with pytest.raises(KeycloakDeprecationError):
        oid.entitlement(token=token["access_token"], resource_server_id=resource_server_id)


def test_introspect(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test introspect.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)

    assert oid.introspect(token=token["access_token"])["active"]
    assert oid.introspect(
        token=token["access_token"], rpt="some", token_type_hint="requesting_party_token",
    ) == {"active": False}

    with pytest.raises(KeycloakRPTNotFound):
        oid.introspect(token=token["access_token"], token_type_hint="requesting_party_token")


def test_decode_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test decode token.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)
    decoded_access_token = oid.decode_token(token=token["access_token"])
    decoded_access_token_2 = oid.decode_token(token=token["access_token"], validate=False)
    decoded_refresh_token = oid.decode_token(token=token["refresh_token"], validate=False)

    assert decoded_access_token == decoded_access_token_2
    assert decoded_access_token["preferred_username"] == username, decoded_access_token
    assert decoded_refresh_token["typ"] == "Refresh", decoded_refresh_token


def test_decode_token_invalid_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test decode token with an invalid token.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = oid.token(username=username, password=password)
    access_token = token["access_token"]
    decoded_access_token = oid.decode_token(token=access_token)

    key = oid.public_key()
    key = "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
    key = jwcrypto.jwk.JWK.from_pem(key.encode("utf-8"))

    invalid_access_token = access_token + "a"
    with pytest.raises(jwcrypto.jws.InvalidJWSSignature):
        decoded_invalid_access_token = oid.decode_token(token=invalid_access_token, validate=True)

    with pytest.raises(jwcrypto.jws.InvalidJWSSignature):
        decoded_invalid_access_token = oid.decode_token(
            token=invalid_access_token, validate=True, key=key,
        )

    decoded_invalid_access_token = oid.decode_token(token=invalid_access_token, validate=False)
    assert decoded_access_token == decoded_invalid_access_token

    decoded_invalid_access_token = oid.decode_token(
        token=invalid_access_token, validate=False, key=key,
    )
    assert decoded_access_token == decoded_invalid_access_token


def test_load_authorization_config(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test load authorization config.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz

    oid.load_authorization_config(path="tests/data/authz_settings.json")
    assert "test-authz-rb-policy" in oid.authorization.policies
    assert isinstance(oid.authorization.policies["test-authz-rb-policy"], Policy)
    assert len(oid.authorization.policies["test-authz-rb-policy"].roles) == 1
    assert isinstance(oid.authorization.policies["test-authz-rb-policy"].roles[0], Role)
    assert len(oid.authorization.policies["test-authz-rb-policy"].permissions) == 2
    assert isinstance(
        oid.authorization.policies["test-authz-rb-policy"].permissions[0], Permission,
    )


def test_get_policies(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        oid.get_policies(token=token["access_token"])

    oid.load_authorization_config(path="tests/data/authz_settings.json")
    assert oid.get_policies(token=token["access_token"]) is None

    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert oid.get_policies(token=token["access_token"], method_token_info="decode") == []
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    oid.authorization.policies["test"] = policy
    assert [
        str(x) for x in oid.get_policies(token=token["access_token"], method_token_info="decode")
    ] == ["Policy: test (role)"]
    assert [
        repr(x) for x in oid.get_policies(token=token["access_token"], method_token_info="decode")
    ] == ["<Policy: test (role)>"]
    oid.client_id = orig_client_id

    oid.logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        oid.get_policies(token=token["access_token"])


def test_get_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        oid.get_permissions(token=token["access_token"])

    oid.load_authorization_config(path="tests/data/authz_settings.json")
    assert oid.get_permissions(token=token["access_token"]) is None

    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert oid.get_permissions(token=token["access_token"], method_token_info="decode") == []
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    policy.add_permission(
        permission=Permission(
            name="test-perm", type="resource", logic="POSITIVE", decision_strategy="UNANIMOUS",
        ),
    )
    oid.authorization.policies["test"] = policy
    assert [
        str(x)
        for x in oid.get_permissions(token=token["access_token"], method_token_info="decode")
    ] == ["Permission: test-perm (resource)"]
    assert [
        repr(x)
        for x in oid.get_permissions(token=token["access_token"], method_token_info="decode")
    ] == ["<Permission: test-perm (resource)>"]
    oid.client_id = orig_client_id

    oid.logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        oid.get_permissions(token=token["access_token"])


def test_uma_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test UMA permissions.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)

    assert len(oid.uma_permissions(token=token["access_token"])) == 1
    assert oid.uma_permissions(token=token["access_token"])[0]["rsname"] == "Default Resource"


def test_has_uma_access(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test has UMA access.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    oid, username, password = oid_with_credentials_authz
    token = oid.token(username=username, password=password)

    assert (
        str(oid.has_uma_access(token=token["access_token"], permissions=""))
        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
    )
    assert (
        str(oid.has_uma_access(token=token["access_token"], permissions="Default Resource"))
        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
    )

    with pytest.raises(KeycloakPostError):
        oid.has_uma_access(token=token["access_token"], permissions="Does not exist")

    oid.logout(refresh_token=token["refresh_token"])
    assert (
        str(oid.has_uma_access(token=token["access_token"], permissions=""))
        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions=set())"
    )
    assert (
        str(
            oid.has_uma_access(
                token=admin.connection.token["access_token"], permissions="Default Resource",
            ),
        )
        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions="
        + "{'Default Resource'})"
    )


def test_device(oid_with_credentials_device: Tuple[KeycloakOpenID, str, str]):
    """Test device authorization flow.

    :param oid_with_credentials_device: Keycloak OpenID client with pre-configured user
        credentials and device authorization flow enabled
    :type oid_with_credentials_device: Tuple[KeycloakOpenID, str, str]
    """
    oid, _, _ = oid_with_credentials_device
    res = oid.device()
    assert res == {
        "device_code": mock.ANY,
        "user_code": mock.ANY,
        "verification_uri": f"http://localhost:8081/realms/{oid.realm_name}/device",
        "verification_uri_complete": f"http://localhost:8081/realms/{oid.realm_name}/"
        + f"device?user_code={res['user_code']}",
        "expires_in": 600,
        "interval": 5,
    }


# async function start


@pytest.mark.asyncio
async def test_a_well_known(oid: KeycloakOpenID):
    """Test the well_known method.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    res = await oid.a_well_known()
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


@pytest.mark.asyncio
async def test_a_auth_url(env, oid: KeycloakOpenID):
    """Test the auth_url method.

    :param env: Environment fixture
    :type env: KeycloakTestEnv
    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    res = await oid.a_auth_url(redirect_uri="http://test.test/*")
    assert (
        res
        == f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}/realms/{oid.realm_name}"
        + f"/protocol/openid-connect/auth?client_id={oid.client_id}&response_type=code"
        + "&redirect_uri=http://test.test/*&scope=email&state=&nonce="
    )


@pytest.mark.asyncio
async def test_a_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test the token method.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.a_token(username=username, password=password)
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with dummy totp
    token = await oid.a_token(username=username, password=password, totp="123456")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with extra param
    token = await oid.a_token(username=username, password=password, extra_param="foo")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": mock.ANY,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": mock.ANY,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }


@pytest.mark.asyncio
async def test_a_exchange_token(
    oid_with_credentials: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test the exchange token method.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    # Verify existing user
    oid, username, password = oid_with_credentials

    # Allow impersonation
    await admin.a_change_current_realm(oid.realm_name)
    await admin.a_assign_client_role(
        user_id=await admin.a_get_user_id(username=username),
        client_id=await admin.a_get_client_id(client_id="realm-management"),
        roles=[
            await admin.a_get_client_role(
                client_id=admin.get_client_id(client_id="realm-management"),
                role_name="impersonation",
            ),
        ],
    )

    token = await oid.a_token(username=username, password=password)
    assert await oid.a_userinfo(token=token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": True,
        "family_name": "last",
        "given_name": "first",
        "name": "first last",
        "preferred_username": username,
        "sub": mock.ANY,
    }

    # Exchange token with the new user
    new_token = oid.exchange_token(
        token=token["access_token"], audience=oid.client_id, subject=username,
    )
    assert await oid.a_userinfo(token=new_token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": True,
        "family_name": "last",
        "given_name": "first",
        "name": "first last",
        "preferred_username": username,
        "sub": mock.ANY,
    }
    assert token != new_token


@pytest.mark.asyncio
async def test_a_logout(oid_with_credentials):
    """Test logout.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials

    token = await oid.a_token(username=username, password=password)
    assert await oid.a_userinfo(token=token["access_token"]) != dict()
    assert await oid.a_logout(refresh_token=token["refresh_token"]) == dict()

    with pytest.raises(KeycloakAuthenticationError):
        await oid.a_userinfo(token=token["access_token"])


@pytest.mark.asyncio
async def test_a_certs(oid: KeycloakOpenID):
    """Test certificates.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    assert len((await oid.a_certs())["keys"]) == 2


@pytest.mark.asyncio
async def test_a_public_key(oid: KeycloakOpenID):
    """Test public key.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    assert await oid.a_public_key() is not None


@pytest.mark.asyncio
async def test_a_entitlement(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test entitlement.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.a_token(username=username, password=password)
    resource_server_id = admin.get_client_authz_resources(
        client_id=admin.get_client_id(oid.client_id),
    )[0]["_id"]

    with pytest.raises(KeycloakDeprecationError):
        await oid.a_entitlement(token=token["access_token"], resource_server_id=resource_server_id)


@pytest.mark.asyncio
async def test_a_introspect(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test introspect.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.a_token(username=username, password=password)

    assert (await oid.a_introspect(token=token["access_token"]))["active"]
    assert await oid.a_introspect(
        token=token["access_token"], rpt="some", token_type_hint="requesting_party_token",
    ) == {"active": False}

    with pytest.raises(KeycloakRPTNotFound):
        await oid.a_introspect(
            token=token["access_token"], token_type_hint="requesting_party_token",
        )


@pytest.mark.asyncio
async def test_a_decode_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test decode token asynchronously.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.a_token(username=username, password=password)
    decoded_access_token = await oid.a_decode_token(token=token["access_token"])
    decoded_access_token_2 = await oid.a_decode_token(token=token["access_token"], validate=False)
    decoded_refresh_token = await oid.a_decode_token(token=token["refresh_token"], validate=False)

    assert decoded_access_token == decoded_access_token_2
    assert decoded_access_token["preferred_username"] == username, decoded_access_token
    assert decoded_refresh_token["typ"] == "Refresh", decoded_refresh_token


@pytest.mark.asyncio
async def test_a_decode_token_invalid_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test decode token asynchronously an invalid token.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.a_token(username=username, password=password)
    access_token = token["access_token"]
    decoded_access_token = await oid.a_decode_token(token=access_token)

    key = await oid.a_public_key()
    key = "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
    key = jwcrypto.jwk.JWK.from_pem(key.encode("utf-8"))

    invalid_access_token = access_token + "a"
    with pytest.raises(jwcrypto.jws.InvalidJWSSignature):
        decoded_invalid_access_token = await oid.a_decode_token(
            token=invalid_access_token, validate=True,
        )

    with pytest.raises(jwcrypto.jws.InvalidJWSSignature):
        decoded_invalid_access_token = await oid.a_decode_token(
            token=invalid_access_token, validate=True, key=key,
        )

    decoded_invalid_access_token = await oid.a_decode_token(
        token=invalid_access_token, validate=False,
    )
    assert decoded_access_token == decoded_invalid_access_token

    decoded_invalid_access_token = await oid.a_decode_token(
        token=invalid_access_token, validate=False, key=key,
    )
    assert decoded_access_token == decoded_invalid_access_token


@pytest.mark.asyncio
async def test_a_load_authorization_config(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str],
):
    """Test load authorization config.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz

    await oid.a_load_authorization_config(path="tests/data/authz_settings.json")
    assert "test-authz-rb-policy" in oid.authorization.policies
    assert isinstance(oid.authorization.policies["test-authz-rb-policy"], Policy)
    assert len(oid.authorization.policies["test-authz-rb-policy"].roles) == 1
    assert isinstance(oid.authorization.policies["test-authz-rb-policy"].roles[0], Role)
    assert len(oid.authorization.policies["test-authz-rb-policy"].permissions) == 2
    assert isinstance(
        oid.authorization.policies["test-authz-rb-policy"].permissions[0], Permission,
    )


@pytest.mark.asyncio
async def test_a_has_uma_access(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin,
):
    """Test has UMA access.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.a_token(username=username, password=password)

    assert (
        str(await oid.a_has_uma_access(token=token["access_token"], permissions=""))
        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
    )
    assert (
        str(
            await oid.a_has_uma_access(token=token["access_token"], permissions="Default Resource"),
        )
        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
    )

    with pytest.raises(KeycloakPostError):
        await oid.a_has_uma_access(token=token["access_token"], permissions="Does not exist")

    await oid.a_logout(refresh_token=token["refresh_token"])
    assert (
        str(await oid.a_has_uma_access(token=token["access_token"], permissions=""))
        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions=set())"
    )
    assert (
        str(
            await oid.a_has_uma_access(
                token=admin.connection.token["access_token"], permissions="Default Resource",
            ),
        )
        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions="
        + "{'Default Resource'})"
    )


@pytest.mark.asyncio
async def test_a_get_policies(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.a_token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        await oid.a_get_policies(token=token["access_token"])

    await oid.a_load_authorization_config(path="tests/data/authz_settings.json")
    assert await oid.a_get_policies(token=token["access_token"]) is None

    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert await oid.a_get_policies(token=token["access_token"], method_token_info="decode") == []
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    oid.authorization.policies["test"] = policy
    assert [
        str(x)
        for x in await oid.a_get_policies(token=token["access_token"], method_token_info="decode")
    ] == ["Policy: test (role)"]
    assert [
        repr(x)
        for x in await oid.a_get_policies(token=token["access_token"], method_token_info="decode")
    ] == ["<Policy: test (role)>"]
    oid.client_id = orig_client_id

    await oid.a_logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        await oid.a_get_policies(token=token["access_token"])


@pytest.mark.asyncio
async def test_a_get_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.a_token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        await oid.a_get_permissions(token=token["access_token"])

    await oid.a_load_authorization_config(path="tests/data/authz_settings.json")
    assert await oid.a_get_permissions(token=token["access_token"]) is None

    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert (
        await oid.a_get_permissions(token=token["access_token"], method_token_info="decode") == []
    )
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    policy.add_permission(
        permission=Permission(
            name="test-perm", type="resource", logic="POSITIVE", decision_strategy="UNANIMOUS",
        ),
    )
    oid.authorization.policies["test"] = policy
    assert [
        str(x)
        for x in await oid.a_get_permissions(
            token=token["access_token"], method_token_info="decode",
        )
    ] == ["Permission: test-perm (resource)"]
    assert [
        repr(x)
        for x in await oid.a_get_permissions(
            token=token["access_token"], method_token_info="decode",
        )
    ] == ["<Permission: test-perm (resource)>"]
    oid.client_id = orig_client_id

    await oid.a_logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        await oid.a_get_permissions(token=token["access_token"])


@pytest.mark.asyncio
async def test_a_uma_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test UMA permissions.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.a_token(username=username, password=password)

    assert len(await oid.a_uma_permissions(token=token["access_token"])) == 1
    assert (await oid.a_uma_permissions(token=token["access_token"]))[0][
        "rsname"
    ] == "Default Resource"


@pytest.mark.asyncio
async def test_a_device(oid_with_credentials_device: Tuple[KeycloakOpenID, str, str]):
    """Test device authorization flow.

    :param oid_with_credentials_device: Keycloak OpenID client with pre-configured user
        credentials and device authorization flow enabled
    :type oid_with_credentials_device: Tuple[KeycloakOpenID, str, str]
    """
    oid, _, _ = oid_with_credentials_device
    res = await oid.a_device()
    assert res == {
        "device_code": mock.ANY,
        "user_code": mock.ANY,
        "verification_uri": f"http://localhost:8081/realms/{oid.realm_name}/device",
        "verification_uri_complete": f"http://localhost:8081/realms/{oid.realm_name}/"
        + f"device?user_code={res['user_code']}",
        "expires_in": 600,
        "interval": 5,
    }


def test_counter_part():
    """Test that each function has its async counter part."""
    openid_methods = [
        func for func in dir(KeycloakOpenID) if callable(getattr(KeycloakOpenID, func))
    ]
    sync_methods = [
        method
        for method in openid_methods
        if not method.startswith("a_") and not method.startswith("_")
    ]
    async_methods = [
        method for method in openid_methods if iscoroutinefunction(getattr(KeycloakOpenID, method))
    ]

    for method in sync_methods:
        async_method = f"a_{method}"
        assert (async_method in openid_methods) is True
        sync_sign = signature(getattr(KeycloakOpenID, method))
        async_sign = signature(getattr(KeycloakOpenID, async_method))
        assert sync_sign.parameters == async_sign.parameters

    for async_method in async_methods:
        if async_method[2:].startswith("_"):
            continue

        assert async_method[2:] in sync_methods
