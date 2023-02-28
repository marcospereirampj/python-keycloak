# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Keycloak OpenID module.

The module contains mainly the implementation of KeycloakOpenID class, the main
class to handle authentication and token manipulation.
"""

import json
from datetime import datetime, timedelta

from jose import jwt

from .authorization import Authorization
from .connection import ConnectionManager
from .exceptions import (
    KeycloakAuthenticationError,
    KeycloakAuthorizationConfigError,
    KeycloakDeprecationError,
    KeycloakGetError,
    KeycloakInvalidTokenError,
    KeycloakPostError,
    KeycloakRPTNotFound,
    raise_error_from_response,
)
from .uma_permissions import AuthStatus, build_permission_param
from .urls_patterns import (
    URL_AUTH,
    URL_CERTS,
    URL_ENTITLEMENT,
    URL_INTROSPECT,
    URL_LOGOUT,
    URL_REALM,
    URL_TOKEN,
    URL_USERINFO,
    URL_WELL_KNOWN,
)


class KeycloakOpenID:
    """Keycloak OpenID client.

    :param server_url: Keycloak server url
    :param client_id: client id
    :param realm_name: realm name
    :param client_secret_key: client secret key
    :param verify: True if want check connection SSL
    :param custom_headers: dict of custom header to pass to each HTML request
    :param proxies: dict of proxies to sent the request by.
    :param timeout: connection timeout in seconds
    """

    def __init__(
        self,
        server_url,
        realm_name,
        client_id,
        client_secret_key=None,
        verify=True,
        custom_headers=None,
        proxies=None,
        timeout=60,
    ):
        """Init method.

        :param server_url: Keycloak server url
        :type server_url: str
        :param client_id: client id
        :type client_id: str
        :param realm_name: realm name
        :type realm_name: str
        :param client_secret_key: client secret key
        :type client_secret_key: str
        :param verify: True if want check connection SSL
        :type verify: bool
        :param custom_headers: dict of custom header to pass to each HTML request
        :type custom_headers: dict
        :param proxies: dict of proxies to sent the request by.
        :type proxies: dict
        :param timeout: connection timeout in seconds
        :type timeout: int
        """
        self.client_id = client_id
        self.client_secret_key = client_secret_key
        self.realm_name = realm_name
        headers = custom_headers if custom_headers is not None else dict()
        self.connection = ConnectionManager(
            base_url=server_url, headers=headers, timeout=timeout, verify=verify, proxies=proxies
        )

        self.authorization = Authorization()

    @property
    def client_id(self):
        """Get client id.

        :returns: Client id
        :rtype: str
        """
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        """Get the client secret key.

        :returns: Client secret key
        :rtype: str
        """
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def realm_name(self):
        """Get the realm name.

        :returns: Realm name
        :rtype: str
        """
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def connection(self):
        """Get connection.

        :returns: Connection manager object
        :rtype: ConnectionManager
        """
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    def authorization(self):
        """Get authorization.

        :returns: The authorization manager
        :rtype: Authorization
        """
        return self._authorization

    @authorization.setter
    def authorization(self, value):
        self._authorization = value

    def _add_secret_key(self, payload):
        """Add secret key if exists.

        :param payload: Payload
        :type payload: dict
        :returns: Payload with the secret key
        :rtype: dict
        """
        if self.client_secret_key:
            payload.update({"client_secret": self.client_secret_key})

        return payload

    def _build_name_role(self, role):
        """Build name of a role.

        :param role: Role name
        :type role: str
        :returns: Role path
        :rtype: str
        """
        return self.client_id + "/" + role

    def _token_info(self, token, method_token_info, **kwargs):
        """Getter for the token data.

        :param token: Token
        :type token: str
        :param method_token_info: Token info method to use
        :type method_token_info: str
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Token info
        :rtype: dict
        """
        if method_token_info == "introspect":
            token_info = self.introspect(token)
        else:
            token_info = self.decode_token(token, **kwargs)

        return token_info

    def well_known(self):
        """Get the well_known object.

        The most important endpoint to understand is the well-known configuration
        endpoint. It lists endpoints and other configuration options relevant to
        the OpenID Connect implementation in Keycloak.

        :returns: It lists endpoints and other configuration options relevant
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_WELL_KNOWN.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def auth_url(self, redirect_uri, scope="email", state=""):
        """Get authorization URL endpoint.

        :param redirect_uri: Redirect url to receive oauth code
        :type redirect_uri: str
        :param scope: Scope of authorization request, split with the blank space
        :type scope: str
        :param state: State will be returned to the redirect_uri
        :type state: str
        :returns: Authorization URL Full Build
        :rtype: str
        """
        params_path = {
            "authorization-endpoint": self.well_known()["authorization_endpoint"],
            "client-id": self.client_id,
            "redirect-uri": redirect_uri,
            "scope": scope,
            "state": state,
        }
        return URL_AUTH.format(**params_path)

    def token(
        self,
        username="",
        password="",
        grant_type=["password"],
        code="",
        redirect_uri="",
        totp=None,
        scope="openid",
        **extra
    ):
        """Retrieve user token.

        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param username: Username
        :type username: str
        :param password: Password
        :type password: str
        :param grant_type: Grant type
        :type grant_type: str
        :param code: Code
        :type code: str
        :param redirect_uri: Redirect URI
        :type redirect_uri: str
        :param totp: Time-based one-time password
        :type totp: int
        :param scope: Scope, defaults to openid
        :type scope: str
        :param extra: Additional extra arguments
        :type extra: dict
        :returns: Keycloak token
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        payload = {
            "username": username,
            "password": password,
            "client_id": self.client_id,
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if extra:
            payload.update(extra)

        if totp:
            payload["totp"] = totp

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def refresh_token(self, refresh_token, grant_type=["refresh_token"]):
        """Refresh the user token.

        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param refresh_token: Refresh token from Keycloak
        :type refresh_token: str
        :param grant_type: Grant type
        :type grant_type: str
        :returns: New token
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        payload = {
            "client_id": self.client_id,
            "grant_type": grant_type,
            "refresh_token": refresh_token,
        }
        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def exchange_token(
        self,
        token: str,
        client_id: str,
        audience: str,
        subject: str,
        requested_token_type: str = "urn:ietf:params:oauth:token-type:refresh_token",
        scope: str = "openid",
    ) -> dict:
        """Exchange user token.

        Use a token to obtain an entirely different token. See
        https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange

        :param token: Access token
        :type token: str
        :param client_id: Client id
        :type client_id: str
        :param audience: Audience
        :type audience: str
        :param subject: Subject
        :type subject: str
        :param requested_token_type: Token type specification
        :type requested_token_type: str
        :param scope: Scope, defaults to openid
        :type scope: str
        :returns: Exchanged token
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        payload = {
            "grant_type": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "client_id": client_id,
            "subject_token": token,
            "requested_token_type": requested_token_type,
            "audience": audience,
            "requested_subject": subject,
            "scope": scope,
        }
        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def userinfo(self, token):
        """Get the user info object.

        The userinfo endpoint returns standard claims about the authenticated user,
        and is protected by a bearer token.

        http://openid.net/specs/openid-connect-core-1_0.html#UserInfo

        :param token: Access token
        :type token: str
        :returns: Userinfo object
        :rtype: dict
        """
        self.connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_USERINFO.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def logout(self, refresh_token):
        """Log out the authenticated user.

        :param refresh_token: Refresh token from Keycloak
        :type refresh_token: str
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        payload = {"client_id": self.client_id, "refresh_token": refresh_token}
        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_LOGOUT.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def certs(self):
        """Get certificates.

        The certificate endpoint returns the public keys enabled by the realm, encoded as a
        JSON Web Key (JWK). Depending on the realm settings there can be one or more keys enabled
        for verifying tokens.

        https://tools.ietf.org/html/rfc7517

        :returns: Certificates
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_CERTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def public_key(self):
        """Retrieve the public key.

        The public key is exposed by the realm page directly.

        :returns: The public key
        :rtype: str
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)["public_key"]

    def entitlement(self, token, resource_server_id):
        """Get entitlements from the token.

        Client applications can use a specific endpoint to obtain a special security token
        called a requesting party token (RPT). This token consists of all the entitlements
        (or permissions) for a user as a result of the evaluation of the permissions and
        authorization policies associated with the resources being requested. With an RPT,
        client applications can gain access to protected resources at the resource server.

        :param token: Access token
        :type token: str
        :param resource_server_id: Resource server ID
        :type resource_server_id: str
        :returns: Entitlements
        :rtype: dict
        """
        self.connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self.realm_name, "resource-server-id": resource_server_id}
        data_raw = self.connection.raw_get(URL_ENTITLEMENT.format(**params_path))

        if data_raw.status_code == 404:
            return raise_error_from_response(data_raw, KeycloakDeprecationError)

        return raise_error_from_response(data_raw, KeycloakGetError)  # pragma: no cover

    def introspect(self, token, rpt=None, token_type_hint=None):
        """Introspect the user token.

        The introspection endpoint is used to retrieve the active state of a token.
        It is can only be invoked by confidential clients.

        https://tools.ietf.org/html/rfc7662

        :param token: Access token
        :type token: str
        :param rpt: Requesting party token
        :type rpt: str
        :param token_type_hint: Token type hint
        :type token_type_hint: str

        :returns: Token info
        :rtype: dict
        :raises KeycloakRPTNotFound: In case of RPT not specified
        """
        params_path = {"realm-name": self.realm_name}
        payload = {"client_id": self.client_id, "token": token}

        if token_type_hint == "requesting_party_token":
            if rpt:
                payload.update({"token": rpt, "token_type_hint": token_type_hint})
                self.connection.add_param_headers("Authorization", "Bearer " + token)
            else:
                raise KeycloakRPTNotFound("Can't found RPT.")

        payload = self._add_secret_key(payload)

        data_raw = self.connection.raw_post(URL_INTROSPECT.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def decode_token(self, token, key, algorithms=["RS256"], **kwargs):
        """Decode user token.

        A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
        structure that represents a cryptographic key.  This specification
        also defines a JWK Set JSON data structure that represents a set of
        JWKs.  Cryptographic algorithms and identifiers for use with this
        specification are described in the separate JSON Web Algorithms (JWA)
        specification and IANA registries established by that specification.

        https://tools.ietf.org/html/rfc7517

        :param token: Keycloak token
        :type token: str
        :param key: Decode key
        :type key: str
        :param algorithms: Algorithms to use for decoding
        :type algorithms: list[str]
        :param kwargs: Keyword arguments
        :type kwargs: dict
        :returns: Decoded token
        :rtype: dict
        """
        return jwt.decode(token, key, algorithms=algorithms, audience=self.client_id, **kwargs)

    def load_authorization_config(self, path):
        """Load Keycloak settings (authorization).

        :param path: settings file (json)
        :type path: str
        """
        with open(path, "r") as fp:
            authorization_json = json.load(fp)

        self.authorization.load_config(authorization_json)

    def get_policies(self, token, method_token_info="introspect", **kwargs):
        """Get policies by user token.

        :param token: User token
        :type token: str
        :param method_token_info: Method for token info decoding
        :type method_token_info: str
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :return: Policies
        :rtype: dict
        :raises KeycloakAuthorizationConfigError: In case of bad authorization configuration
        :raises KeycloakInvalidTokenError: In case of bad token
        """
        if not self.authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = self._token_info(token, method_token_info, **kwargs)

        if method_token_info == "introspect" and not token_info["active"]:
            raise KeycloakInvalidTokenError("Token expired or invalid.")

        user_resources = token_info["resource_access"].get(self.client_id)

        if not user_resources:
            return None

        policies = []

        for policy_name, policy in self.authorization.policies.items():
            for role in user_resources["roles"]:
                if self._build_name_role(role) in policy.roles:
                    policies.append(policy)

        return list(set(policies))

    def get_permissions(self, token, method_token_info="introspect", **kwargs):
        """Get permission by user token.

        :param token: user token
        :type token: str
        :param method_token_info: Decode token method
        :type method_token_info: str
        :param kwargs: parameters for decode
        :type kwargs: dict
        :returns: permissions list
        :rtype: list
        :raises KeycloakAuthorizationConfigError: In case of bad authorization configuration
        :raises KeycloakInvalidTokenError: In case of bad token
        """
        if not self.authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = self._token_info(token, method_token_info, **kwargs)

        if method_token_info == "introspect" and not token_info["active"]:
            raise KeycloakInvalidTokenError("Token expired or invalid.")

        user_resources = token_info["resource_access"].get(self.client_id)

        if not user_resources:
            return None

        permissions = []

        for policy_name, policy in self.authorization.policies.items():
            for role in user_resources["roles"]:
                if self._build_name_role(role) in policy.roles:
                    permissions += policy.permissions

        return list(set(permissions))

    def uma_permissions(self, token, permissions=""):
        """Get UMA permissions by user token with requested permissions.

        The token endpoint is used to retrieve UMA permissions from Keycloak. It can only be
        invoked by confidential clients.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param token: user token
        :type token: str
        :param permissions: list of uma permissions list(resource:scope) requested by the user
        :type permissions: str
        :returns: Keycloak server response
        :rtype: dict
        """
        permission = build_permission_param(permissions)

        params_path = {"realm-name": self.realm_name}
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": permission,
            "response_mode": "permissions",
            "audience": self.client_id,
        }

        self.connection.add_param_headers("Authorization", "Bearer " + token)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def has_uma_access(self, token, permissions):
        """Determine whether user has uma permissions with specified user token.

        :param token: user token
        :type token: str
        :param permissions: list of uma permissions (resource:scope)
        :type permissions: str
        :return: Authentication status
        :rtype: AuthStatus
        :raises KeycloakAuthenticationError: In case of failed authentication
        :raises KeycloakPostError: In case of failed request to Keycloak
        """
        needed = build_permission_param(permissions)
        try:
            granted = self.uma_permissions(token, permissions)
        except (KeycloakPostError, KeycloakAuthenticationError) as e:
            if e.response_code == 403:  # pragma: no cover
                return AuthStatus(
                    is_logged_in=True, is_authorized=False, missing_permissions=needed
                )
            elif e.response_code == 401:
                return AuthStatus(
                    is_logged_in=False, is_authorized=False, missing_permissions=needed
                )
            raise

        for resource_struct in granted:
            resource = resource_struct["rsname"]
            scopes = resource_struct.get("scopes", None)
            if not scopes:
                needed.discard(resource)
                continue
            for scope in scopes:  # pragma: no cover
                needed.discard("{}#{}".format(resource, scope))

        return AuthStatus(
            is_logged_in=True, is_authorized=len(needed) == 0, missing_permissions=needed
        )


class KeycloakOpenIDConnectionManager(ConnectionManager):
    """A class to help with OpenID connections which can auto refresh tokens.

    :param object: _description_
    :type object: _type_
    """

    _server_url = None
    _username = None
    _password = None
    _totp = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _connection = None
    _custom_headers = None
    _user_realm_name = None
    _expires_at = None

    def __init__(
        self,
        server_url,
        username=None,
        password=None,
        token=None,
        totp=None,
        realm_name="master",
        client_id="admin-cli",
        verify=True,
        client_secret_key=None,
        custom_headers=None,
        user_realm_name=None,
        timeout=60,
    ):
        """Init method.

        :param server_url: Keycloak server url
        :type server_url: str
        :param username: admin username
        :type username: str
        :param password: admin password
        :type password: str
        :param token: access and refresh tokens
        :type token: dict
        :param totp: Time based OTP
        :type totp: str
        :param realm_name: realm name
        :type realm_name: str
        :param client_id: client id
        :type client_id: str
        :param verify: True if want check connection SSL
        :type verify: bool
        :param client_secret_key: client secret key
            (optional, required only for access type confidential)
        :type client_secret_key: str
        :param custom_headers: dict of custom header to pass to each HTML request
        :type custom_headers: dict
        :param user_realm_name: The realm name of the user, if different from realm_name
        :type user_realm_name: str
        :param timeout: connection timeout in seconds
        :type timeout: int
        """
        # token is renewed when it hits 90% of its lifetime. This is to account for any possible
        # clock skew.
        self.token_renewal_fraction = 0.9
        self.server_url = server_url
        self.username = username
        self.password = password
        self.token = token
        self.totp = totp
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.user_realm_name = user_realm_name
        self.timeout = timeout

        if self.token is None:
            self.get_token()

        self.headers = (
            {
                "Authorization": "Bearer " + self.token.get("access_token"),
                "Content-Type": "application/json",
            }
            if self.token is not None
            else {}
        )
        self.custom_headers = custom_headers

        super().__init__(
            base_url=self.server_url, headers=self.headers, timeout=60, verify=self.verify
        )

    @property
    def server_url(self):
        """Get server url.

        :returns: Keycloak server url
        :rtype: str
        """
        return self.base_url

    @server_url.setter
    def server_url(self, value):
        self.base_url = value

    @property
    def realm_name(self):
        """Get realm name.

        :returns: Realm name
        :rtype: str
        """
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def client_id(self):
        """Get client id.

        :returns: Client id
        :rtype: str
        """
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        """Get client secret key.

        :returns: Client secret key
        :rtype: str
        """
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def username(self):
        """Get username.

        :returns: Admin username
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        """Get password.

        :returns: Admin password
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def totp(self):
        """Get totp.

        :returns: TOTP
        :rtype: str
        """
        return self._totp

    @totp.setter
    def totp(self, value):
        self._totp = value

    @property
    def token(self):
        """Get token.

        :returns: Access and refresh token
        :rtype: dict
        """
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._expires_at = datetime.now() + timedelta(
            seconds=int(self.token_renewal_fraction * self.token["expires_in"] if value else 0)
        )

    @property
    def expires_at(self):
        """Get token expiry time.

        :returns: Datetime at which the current token will expire
        :rtype: datetime
        """
        return self._expires_at

    @property
    def user_realm_name(self):
        """Get user realm name.

        :returns: User realm name
        :rtype: str
        """
        return self._user_realm_name

    @user_realm_name.setter
    def user_realm_name(self, value):
        self._user_realm_name = value

    @property
    def custom_headers(self):
        """Get custom headers.

        :returns: Custom headers
        :rtype: dict
        """
        return self._custom_headers

    @custom_headers.setter
    def custom_headers(self, value):
        self._custom_headers = value
        if self.custom_headers is not None:
            # merge custom headers to main headers
            self.headers.update(self.custom_headers)

    def get_token(self):
        """Get admin token.

        The admin token is then set in the `token` attribute.
        """
        if self.user_realm_name:
            token_realm_name = self.user_realm_name
        elif self.realm_name:
            token_realm_name = self.realm_name
        else:
            token_realm_name = "master"

        self.keycloak_openid = KeycloakOpenID(
            server_url=self.server_url,
            client_id=self.client_id,
            realm_name=token_realm_name,
            verify=self.verify,
            client_secret_key=self.client_secret_key,
            timeout=self.timeout,
        )

        grant_type = []
        if self.client_secret_key:
            if self.user_realm_name:
                self.realm_name = self.user_realm_name
            grant_type.append("client_credentials")
        elif self.username and self.password:
            grant_type.append("password")

        if grant_type:
            self.token = self.keycloak_openid.token(
                self.username, self.password, grant_type=grant_type, totp=self.totp
            )
        else:
            self.token = None

    def refresh_token(self):
        """Refresh the token.

        :raises KeycloakPostError: In case the refresh token request failed.
        """
        refresh_token = self.token.get("refresh_token", None) if self.token else None
        if refresh_token is None:
            self.get_token()
        else:
            try:
                self.token = self.keycloak_openid.refresh_token(refresh_token)
            except KeycloakPostError as e:
                list_errors = [
                    b"Refresh token expired",
                    b"Token is not active",
                    b"Session not active",
                ]
                if e.response_code == 400 and any(err in e.response_body for err in list_errors):
                    self.get_token()
                else:
                    raise

        self.add_param_headers("Authorization", "Bearer " + self.token.get("access_token"))

    def _refresh_if_required(self):
        if datetime.now() >= self.expires_at:
            self.refresh_token()

    def raw_get(self, *args, **kwargs):
        """Call connection.raw_get.

        If auto_refresh is set for *get* and *access_token* is expired, it will refresh the token
        and try *get* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_get(*args, **kwargs)
        return r

    def raw_post(self, *args, **kwargs):
        """Call connection.raw_post.

        If auto_refresh is set for *post* and *access_token* is expired, it will refresh the token
        and try *post* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_post(*args, **kwargs)
        return r

    def raw_put(self, *args, **kwargs):
        """Call connection.raw_put.

        If auto_refresh is set for *put* and *access_token* is expired, it will refresh the token
        and try *put* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_put(*args, **kwargs)
        return r

    def raw_delete(self, *args, **kwargs):
        """Call connection.raw_delete.

        If auto_refresh is set for *delete* and *access_token* is expired,
        it will refresh the token and try *delete* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_delete(*args, **kwargs)
        return r
