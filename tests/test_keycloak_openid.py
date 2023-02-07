"""Test module for KeycloakOpenID."""
from typing import Tuple
from unittest import mock

import pytest

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
from keycloak.keycloak_admin import KeycloakAdmin
from keycloak.keycloak_openid import KeycloakOpenID


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


@pytest.mark.asyncio
async def test_well_known(oid: KeycloakOpenID):
    """Test the well_known method.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    res = await oid.well_known()
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
async def test_auth_url(env, oid: KeycloakOpenID):
    """Test the auth_url method.

    :param env: Environment fixture
    :type env: KeycloakTestEnv
    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    res = await oid.auth_url(redirect_uri="http://test.test/*")
    assert (
        res
        == f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}/realms/{oid.realm_name}"
        + f"/protocol/openid-connect/auth?client_id={oid.client_id}&response_type=code"
        + "&redirect_uri=http://test.test/*&scope=email&state="
    )


@pytest.mark.asyncio
async def test_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test the token method.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.token(username=username, password=password)
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with dummy totp
    token = await oid.token(username=username, password=password, totp="123456")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }

    # Test with extra param
    token = await oid.token(username=username, password=password, extra_param="foo")
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 300,
        "id_token": mock.ANY,
        "not-before-policy": 0,
        "refresh_expires_in": 1800,
        "refresh_token": mock.ANY,
        "scope": mock.ANY,
        "session_state": mock.ANY,
        "token_type": "Bearer",
    }


@pytest.mark.asyncio
async def test_exchange_token(
    oid_with_credentials: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin
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
    admin.realm_name = oid.realm_name
    user_id = await admin.get_user_id(username=username)
    client_id = await admin.get_client_id(client_id="realm-management")
    roles = [await admin.get_client_role(client_id=client_id, role_name="impersonation")]
    print(roles)
    await admin.assign_client_role(user_id=user_id, client_id=client_id, roles=roles)

    token = await oid.token(username=username, password=password)
    assert await oid.userinfo(token=token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": False,
        "preferred_username": username,
        "sub": mock.ANY,
    }

    # Exchange token with the new user
    new_token = await oid.exchange_token(
        token=token["access_token"],
        client_id=oid.client_id,
        audience=oid.client_id,
        subject=username,
    )
    assert await oid.userinfo(token=new_token["access_token"]) == {
        "email": f"{username}@test.test",
        "email_verified": False,
        "preferred_username": username,
        "sub": mock.ANY,
    }
    assert token != new_token


@pytest.mark.asyncio
async def test_logout(oid_with_credentials):
    """Test logout.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials

    token = await oid.token(username=username, password=password)
    assert await oid.userinfo(token=token["access_token"]) != dict()
    assert await oid.logout(refresh_token=token["refresh_token"]) == dict()

    with pytest.raises(KeycloakAuthenticationError):
        await oid.userinfo(token=token["access_token"])


@pytest.mark.asyncio
async def test_certs(oid: KeycloakOpenID):
    """Test certificates.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    certs = await oid.certs()
    assert len(certs["keys"]) == 2


@pytest.mark.asyncio
async def test_public_key(oid: KeycloakOpenID):
    """Test public key.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    """
    assert await oid.public_key() is not None


@pytest.mark.asyncio
async def test_entitlement(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin
):
    """Test entitlement.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.token(username=username, password=password)
    client_id = await admin.get_client_id(oid.client_id)
    with pytest.raises(KeycloakDeprecationError):
        resource_servers = await admin.get_client_authz_resources(client_id=client_id)
        resource_server_id = resource_servers[0]["_id"]
        await oid.entitlement(token=token["access_token"], resource_server_id=resource_server_id)


@pytest.mark.asyncio
async def test_introspect(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test introspect.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.token(username=username, password=password)

    introspect = await oid.introspect(token=token["access_token"])
    assert introspect["active"]

    introspect = await oid.introspect(
        token=token["access_token"], rpt="some", token_type_hint="requesting_party_token"
    )
    assert introspect == {"active": False}

    with pytest.raises(KeycloakRPTNotFound):
        await oid.introspect(token=token["access_token"], token_type_hint="requesting_party_token")


@pytest.mark.asyncio
async def test_decode_token(oid_with_credentials: Tuple[KeycloakOpenID, str, str]):
    """Test decode token.

    :param oid_with_credentials: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials
    token = await oid.token(username=username, password=password)
    public_key = await oid.public_key()

    decoded_token = oid.decode_token(
        token=token["access_token"],
        key="-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----",
        options={"verify_aud": False},
    )
    assert decoded_token["preferred_username"] == username


@pytest.mark.asyncio
async def test_load_authorization_config(
    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
):
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
        oid.authorization.policies["test-authz-rb-policy"].permissions[0], Permission
    )


@pytest.mark.asyncio
async def test_get_policies(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        await oid.get_policies(token=token["access_token"])

    oid.load_authorization_config(path="tests/data/authz_settings.json")
    assert await oid.get_policies(token=token["access_token"]) is None

    key = "-----BEGIN PUBLIC KEY-----\n" + await oid.public_key() + "\n-----END PUBLIC KEY-----"
    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert (
        await oid.get_policies(token=token["access_token"], method_token_info="decode", key=key)
        == []
    )
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    oid.authorization.policies["test"] = policy
    assert [
        str(x)
        for x in await oid.get_policies(
            token=token["access_token"], method_token_info="decode", key=key
        )
    ] == ["Policy: test (role)"]
    assert [
        repr(x)
        for x in await oid.get_policies(
            token=token["access_token"], method_token_info="decode", key=key
        )
    ] == ["<Policy: test (role)>"]
    oid.client_id = orig_client_id

    await oid.logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        await oid.get_policies(token=token["access_token"])


@pytest.mark.asyncio
async def test_get_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    """Test get policies.

    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
        server with client credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    """
    oid, username, password = oid_with_credentials_authz
    token = await oid.token(username=username, password=password)

    with pytest.raises(KeycloakAuthorizationConfigError):
        await oid.get_permissions(token=token["access_token"])

    oid.load_authorization_config(path="tests/data/authz_settings.json")
    assert await oid.get_permissions(token=token["access_token"]) is None

    key = "-----BEGIN PUBLIC KEY-----\n" + await oid.public_key() + "\n-----END PUBLIC KEY-----"
    orig_client_id = oid.client_id
    oid.client_id = "account"
    assert (
        await oid.get_permissions(token=token["access_token"], method_token_info="decode", key=key)
        == []
    )
    policy = Policy(name="test", type="role", logic="POSITIVE", decision_strategy="UNANIMOUS")
    policy.add_role(role="account/view-profile")
    policy.add_permission(
        permission=Permission(
            name="test-perm", type="resource", logic="POSITIVE", decision_strategy="UNANIMOUS"
        )
    )
    oid.authorization.policies["test"] = policy
    assert [
        str(x)
        for x in await oid.get_permissions(
            token=token["access_token"], method_token_info="decode", key=key
        )
    ] == ["Permission: test-perm (resource)"]
    assert [
        repr(x)
        for x in await oid.get_permissions(
            token=token["access_token"], method_token_info="decode", key=key
        )
    ] == ["<Permission: test-perm (resource)>"]
    oid.client_id = orig_client_id

    await oid.logout(refresh_token=token["refresh_token"])
    with pytest.raises(KeycloakInvalidTokenError):
        await oid.get_permissions(token=token["access_token"])


# @pytest.mark.asyncio
# async def test_uma_permissions(oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
#    """Test UMA permissions.
#
#    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
#        server with client credentials
#    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
#    """
#    oid, username, password = oid_with_credentials_authz
#    token = await oid.token(username=username, password=password)
#
#    assert len(await oid.uma_permissions(token=token["access_token"])) == 1
#    uma_permissions = await oid.uma_permissions(token=token["access_token"])
#    assert uma_permissions[0]["rsname"] == "Default Resource"
#
#
# @pytest.mark.asyncio
# async def test_has_uma_access(
#    oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str], admin: KeycloakAdmin
# ):
#    """Test has UMA access.
#
#    :param oid_with_credentials_authz: Keycloak OpenID client configured as an authorization
#        server with client credentials
#    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
#    :param admin: Keycloak Admin client
#    :type admin: KeycloakAdmin
#    """
#    oid, username, password = oid_with_credentials_authz
#    token = await oid.token(username=username, password=password)
#    print(token)
#
#    assert (
#        str(await oid.has_uma_access(token=token["access_token"], permissions=""))
#        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
#    )
#    assert (
#        str(await oid.has_uma_access(token=token["access_token"], permissions="Default Resource"))
#        == "AuthStatus(is_authorized=True, is_logged_in=True, missing_permissions=set())"
#    )
#
#    with pytest.raises(KeycloakPostError):
#        await oid.has_uma_access(token=token["access_token"], permissions="Does not exist")
#
#    await oid.logout(refresh_token=token["refresh_token"])
#    assert (
#        str(await oid.has_uma_access(token=token["access_token"], permissions=""))
#        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions=set())"
#    )
#    assert (
#        str(await oid.has_uma_access(token=admin.token["access_token"], permissions="Default Resource"))
#        == "AuthStatus(is_authorized=False, is_logged_in=False, missing_permissions="
#        + "{'Default Resource'})"
#    )
