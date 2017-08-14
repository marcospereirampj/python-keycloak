"""

"""

import json

from keycloak.exceptions import raise_error_from_response, KeycloakGetError
from .urls_patterns import URL_AUTH, URL_TOKEN, URL_USERINFO, URL_WELL_KNOWN, URL_LOGOUT
from .connection import ConnectionManager


class Keycloak:

    def __init__(self, server_url, client_id, realm_name, client_secret_key=None):
        self.__client_id = client_id
        self.__client_secret_key = client_secret_key
        self.__realm_name = realm_name

        self.__connection = ConnectionManager(base_url=server_url,
                                              headers={},
                                              timeout=60)

    def well_know(self):
        """ The most important endpoint to understand is the well-known configuration
            endpoint. It lists endpoints and other configuration options relevant to
            the OpenID Connect implementation in Keycloak.

            :return It lists endpoints and other configuration options relevant.
        """

        params_path = {"realm-name": self.__realm_name}
        data_raw = self.__connection.raw_get(URL_WELL_KNOWN.format(**params_path))
        raise_error_from_response(data_raw, KeycloakGetError)

        return json.loads(data_raw.text)

    def auth_url(self, redirect_uri):
        """

        http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

        :return:
        """
        return NotImplemented

    def token(self, username, password, grant_type=["password",]):
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param username:
        :param password:
        :param grant_type:
        :return:
        """
        params_path = {"realm-name": self.__realm_name}
        payload = {"username": username, "password": password,
                   "client_id": self.__client_id, "grant_type": grant_type}

        if self.__client_secret_key:
            payload.update({"client_secret": self.__client_secret_key})

        data_raw = self.__connection.raw_post(URL_TOKEN.format(**params_path),
                                              data=payload)
        raise_error_from_response(data_raw, KeycloakGetError)

        return json.loads(data_raw.text)

    def userinfo(self, token):
        """
        The userinfo endpoint returns standard claims about the authenticated user,
        and is protected by a bearer token.

        http://openid.net/specs/openid-connect-core-1_0.html#UserInfo

        :param token:
        :return:
        """

        self.__connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self.__realm_name}

        data_raw = self.__connection.raw_get(URL_USERINFO.format(**params_path))
        raise_error_from_response(data_raw, KeycloakGetError)

        return json.loads(data_raw.text)

    def logout(self, refresh_token):
        """
        The logout endpoint logs out the authenticated user.
        :param refresh_token:
        :return:
        """
        params_path = {"realm-name": self.__realm_name}
        payload = {"client_id": self.__client_id, "refresh_token": refresh_token}

        if self.__client_secret_key:
            payload.update({"client_secret": self.__client_secret_key})

        data_raw = self.__connection.raw_post(URL_LOGOUT.format(**params_path),
                                              data=payload)
        raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

        return None
