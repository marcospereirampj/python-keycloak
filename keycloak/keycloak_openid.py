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

import json

from jose import jwt

from .authorization import Authorization
from .connection import ConnectionManager
from .exceptions import raise_error_from_response, KeycloakGetError, \
    KeycloakRPTNotFound, KeycloakAuthorizationConfigError, KeycloakInvalidTokenError
from .urls_patterns import (
    URL_TOKEN,
    URL_USERINFO,
    URL_WELL_KNOWN,
    URL_LOGOUT,
    URL_CERTS,
    URL_ENTITLEMENT,
    URL_INTROSPECT
)


class KeycloakOpenID:

    def __init__(self, server_url, realm_name, client_id, client_secret_key=None, verify=True):
        """

        :param server_url: Keycloak server url
        :param client_id: client id
        :param realm_name: realm name
        :param client_secret_key: client secret key
        :param verify: True if want check connection SSL
        """
        self._client_id = client_id
        self._client_secret_key = client_secret_key
        self._realm_name = realm_name
        self._connection = ConnectionManager(base_url=server_url,
                                             headers={},
                                             timeout=60,
                                             verify=verify)

        self._authorization = Authorization()

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def realm_name(self):
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, value):
        self._authorization = value

    def _add_secret_key(self, payload):
        """
        Add secret key if exist.

        :param payload:
        :return:
        """
        if self.client_secret_key:
            payload.update({"client_secret": self.client_secret_key})

        return payload

    def _build_name_role(self, role):
        """

        :param role:
        :return:
        """
        return self.client_id + "/" + role

    def _token_info(self, token, method_token_info, **kwargs):
        """

        :param token:
        :param method_token_info:
        :param kwargs:
        :return:
        """
        if method_token_info == 'introspect':
            token_info = self.introspect(token)
        else:
            token_info = self.decode_token(token, **kwargs)

        return token_info

    def well_know(self):
        """ The most important endpoint to understand is the well-known configuration
            endpoint. It lists endpoints and other configuration options relevant to
            the OpenID Connect implementation in Keycloak.

            :return It lists endpoints and other configuration options relevant.
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_WELL_KNOWN.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError)

    def auth_url(self, redirect_uri):
        """

        http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

        :return:
        """
        return NotImplemented

    def token(self, username="", password="", grant_type=["password"], code="", redirect_uri=""):
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param username:
        :param password:
        :param grant_type:
        :param code:
        :param redirect_uri
        :return:
        """
        params_path = {"realm-name": self.realm_name}
        payload = {"username": username, "password": password,
                   "client_id": self.client_id, "grant_type": grant_type,
                   "code": code, "redirect_uri": redirect_uri}

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def refresh_token(self, refresh_token, grant_type=["refresh_token"]):
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param refresh_token:
        :param grant_type:
        :return:
        """
        params_path = {"realm-name": self.realm_name}
        payload = {"client_id": self.client_id, "grant_type": grant_type, "refresh_token": refresh_token}
        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def userinfo(self, token):
        """
        The userinfo endpoint returns standard claims about the authenticated user,
        and is protected by a bearer token.

        http://openid.net/specs/openid-connect-core-1_0.html#UserInfo

        :param token:
        :return:
        """

        self.connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self.realm_name}

        data_raw = self.connection.raw_get(URL_USERINFO.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError)

    def logout(self, refresh_token):
        """
        The logout endpoint logs out the authenticated user.
        :param refresh_token:
        :return:
        """
        params_path = {"realm-name": self.realm_name}
        payload = {"client_id": self.client_id, "refresh_token": refresh_token}

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_LOGOUT.format(**params_path),
                                            data=payload)

        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def certs(self):
        """
        The certificate endpoint returns the public keys enabled by the realm, encoded as a
        JSON Web Key (JWK). Depending on the realm settings there can be one or more keys enabled
        for verifying tokens.

        https://tools.ietf.org/html/rfc7517

        :return:
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_CERTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def entitlement(self, token, resource_server_id):
        """
        Client applications can use a specific endpoint to obtain a special security token
        called a requesting party token (RPT). This token consists of all the entitlements
        (or permissions) for a user as a result of the evaluation of the permissions and authorization
        policies associated with the resources being requested. With an RPT, client applications can
        gain access to protected resources at the resource server.

        :return:
        """
        self.connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self.realm_name, "resource-server-id": resource_server_id}
        data_raw = self.connection.raw_get(URL_ENTITLEMENT.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError)

    def introspect(self, token, rpt=None, token_type_hint=None):
        """
        The introspection endpoint is used to retrieve the active state of a token. It is can only be
        invoked by confidential clients.

        https://tools.ietf.org/html/rfc7662

        :param token:
        :param rpt:
        :param token_type_hint:

        :return:
        """
        params_path = {"realm-name": self.realm_name}

        payload = {"client_id": self.client_id, "token": token}

        if token_type_hint == 'requesting_party_token':
            if rpt:
                payload.update({"token": rpt, "token_type_hint": token_type_hint})
                self.connection.add_param_headers("Authorization", "Bearer " + token)
            else:
                raise KeycloakRPTNotFound("Can't found RPT.")

        payload = self._add_secret_key(payload)

        data_raw = self.connection.raw_post(URL_INTROSPECT.format(**params_path),
                                            data=payload)

        return raise_error_from_response(data_raw, KeycloakGetError)

    def decode_token(self, token, key, algorithms=['RS256'], **kwargs):
        """
        A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
        structure that represents a cryptographic key.  This specification
        also defines a JWK Set JSON data structure that represents a set of
        JWKs.  Cryptographic algorithms and identifiers for use with this
        specification are described in the separate JSON Web Algorithms (JWA)
        specification and IANA registries established by that specification.

        https://tools.ietf.org/html/rfc7517

        :param token:
        :param key:
        :param algorithms:
        :return:
        """

        return jwt.decode(token, key, algorithms=algorithms,
                          audience=self.client_id, **kwargs)

    def load_authorization_config(self, path):
        """
        Load Keycloak settings (authorization)

        :param path: settings file (json)
        :return:
        """
        authorization_file = open(path, 'r')
        authorization_json = json.loads(authorization_file.read())
        self.authorization.load_config(authorization_json)
        authorization_file.close()

    def get_policies(self, token, method_token_info='introspect', **kwargs):
        """
        Get policies by user token

        :param token: user token
        :return: policies list
        """

        if not self.authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = self._token_info(token, method_token_info, **kwargs)

        if method_token_info == 'introspect' and not token_info['active']:
            raise KeycloakInvalidTokenError(
                "Token expired or invalid."
            )

        user_resources = token_info['resource_access'].get(self.client_id)

        if not user_resources:
            return None

        policies = []

        for policy_name, policy in self.authorization.policies.items():
            for role in user_resources['roles']:
                if self._build_name_role(role) in policy.roles:
                    policies.append(policy)

        return list(set(policies))

    def get_permissions(self, token, method_token_info='introspect', **kwargs):
        """
        Get permission by user token

        :param token: user token
        :param method_token_info: Decode token method
        :param kwargs: parameters for decode
        :return: permissions list
        """

        if not self.authorization.policies:
            raise KeycloakAuthorizationConfigError(
                "Keycloak settings not found. Load Authorization Keycloak settings."
            )

        token_info = self._token_info(token, method_token_info, **kwargs)

        if method_token_info == 'introspect' and not token_info['active']:
            raise KeycloakInvalidTokenError(
                "Token expired or invalid."
            )

        user_resources = token_info['resource_access'].get(self.client_id)

        if not user_resources:
            return None

        permissions = []

        for policy_name, policy in self.authorization.policies.items():
            for role in user_resources['roles']:
                if self._build_name_role(role) in policy.roles:
                    permissions += policy.permissions

        return list(set(permissions))
