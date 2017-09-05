# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from keycloak.urls_patterns import URL_ADMIN_USERS_COUNT, URL_ADMIN_USER, URL_ADMIN_USER_CONSENTS, \
    URL_ADMIN_SEND_UPDATE_ACCOUNT, URL_ADMIN_RESET_PASSWORD, URL_ADMIN_SEND_VERIFY_EMAIL, URL_ADMIN_GET_SESSIONS, \
    URL_ADMIN_SERVER_INFO, URL_ADMIN_CLIENTS
from .keycloak_openid import KeycloakOpenID

from .exceptions import raise_error_from_response, KeycloakGetError, KeycloakSecretNotFound, \
    KeycloakRPTNotFound, KeycloakAuthorizationConfigError, KeycloakInvalidTokenError

from .urls_patterns import (
    URL_ADMIN_USERS,
)

from .connection import ConnectionManager
from jose import jwt
import json


class KeycloakAdmin:

    def __init__(self, server_url, username, password, realm_name='master', client_id='admin-cli'):
        self._username = username
        self._password = password
        self._client_id = client_id
        self._realm_name = realm_name

        # Get token Admin
        keycloak_openid = KeycloakOpenID(server_url, client_id, realm_name)
        self._token = keycloak_openid.token(username, password)

        self._connection = ConnectionManager(base_url=server_url,
                                             headers={'Authorization': 'Bearer ' + self.token.get('access_token'),
                                                      'Content-Type': 'application/json'},
                                             timeout=60)

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
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value

    def list_users(self, query=None):
        """
        Get users Returns a list of users, filtered according to query parameters

        :return: users list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_USERS.format(**params_path), **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_user(self, payload):
        """
        Create a new user Username must be unique

        UserRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(URL_ADMIN_USERS.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201)

    def count_users(self):
        """
        User counter

        :return: counter
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_USERS_COUNT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user(self, user_id):
        """
        Get representation of the user

        :param user_id: User id

        UserRepresentation: http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_userrepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_user(self, user_id, payload):
        """
        Update the user

        :param user_id: User id
        :param payload: UserRepresentation

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(URL_ADMIN_USER.format(**params_path),
                                           data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def delete_user(self, user_id):
        """
        Delete the user

        :param user_id: User id

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def consents_user(self, user_id):
        """
        Get consents granted by the user

        :param user_id: User id

        :return: consents
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(URL_ADMIN_USER_CONSENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def send_update_account(self, user_id, payload, client_id=None, lifespan=None, redirect_uri=None):
        """
        Send a update account email to the user An email contains a
        link the user can click to perform a set of required actions.

        :param user_id:
        :param payload:
        :param client_id:
        :param lifespan:
        :param redirect_uri:

        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
                                           data=payload, **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def reset_password(self, user_id, password):
        """
        Set up a temporary password for the user User will have to reset the
        temporary password next time they log in.

        :param user_id: User id
        :param password: A Temporary password

        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(URL_ADMIN_RESET_PASSWORD.format(**params_path),
                                           data=json.dumps({'pass': password}))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def send_verify_email(self, user_id, client_id=None, redirect_uri=None):
        """
        Send a update account email to the user An email contains a
        link the user can click to perform a set of required actions.

        :param user_id: User id
        :param client_id: Client id
        :param redirect_uri: Redirect uri

        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
                                           data={}, **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_sessions(self, user_id):
        """
        Get sessions associated with the user

        :param user_id: User id

        UserSessionRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_usersessionrepresentation

        :return: UserSessionRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(URL_ADMIN_GET_SESSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_server_info(self):
        """
        Get themes, social providers, auth providers, and event listeners available on this server

        :param user_id: User id

        ServerInfoRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        """
        data_raw = self.connection.raw_get(URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_clients(self):
        """
        Get clients belonging to the realm Returns a list of clients belonging to the realm

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :return: ClientRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

