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

from .urls_patterns import URL_ADMIN_USERS_COUNT, URL_ADMIN_USER, URL_ADMIN_USER_CONSENTS, \
    URL_ADMIN_SEND_UPDATE_ACCOUNT, URL_ADMIN_RESET_PASSWORD, URL_ADMIN_SEND_VERIFY_EMAIL, URL_ADMIN_GET_SESSIONS, \
    URL_ADMIN_SERVER_INFO, URL_ADMIN_CLIENTS, URL_ADMIN_CLIENT, URL_ADMIN_CLIENT_ROLES, URL_ADMIN_REALM_ROLES, \
    URL_ADMIN_USER_CLIENT_ROLES, URL_ADMIN_USER_STORAGE
from .keycloak_openid import KeycloakOpenID

from .exceptions import raise_error_from_response, KeycloakGetError

from .urls_patterns import (
    URL_ADMIN_USERS,
)

from .connection import ConnectionManager
import json


class KeycloakAdmin:

    def __init__(self, server_url, verify, username, password, realm_name='master', client_id='admin-cli'):
        self._username = username
        self._password = password
        self._client_id = client_id
        self._realm_name = realm_name

        # Get token Admin
        keycloak_openid = KeycloakOpenID(server_url=server_url, client_id=client_id, realm_name=realm_name, verify=verify)
        self._token = keycloak_openid.token(username, password)

        self._connection = ConnectionManager(base_url=server_url,
                                             headers={'Authorization': 'Bearer ' + self.token.get('access_token'),
                                                      'Content-Type': 'application/json'},
                                             timeout=60,
                                             verify=verify)

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

    def get_users(self, query=None):
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

    def users_count(self):
        """
        User counter

        :return: counter
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_USERS_COUNT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_id(self, username):
        """
        Get internal keycloak user id from username
        This is required for further actions against this user.

        :param username:
        clientId in UserRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_userrepresentation

        :return: user_id (uuid as string)
        """
        params_path = {"realm-name": self.realm_name, "username": username}
        data_raw = self.connection.raw_get(URL_ADMIN_USERS.format(**params_path))
        data_content = raise_error_from_response(data_raw, KeycloakGetError)

        for user in data_content:
          thisusername = json.dumps(user["username"]).strip('"')
          if thisusername == username:
            return json.dumps(user["id"]).strip('"')

        return None

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

    def get_client_id(self, client_id_name):
        """
        Get internal keycloak client id from client-id.
        This is required for further actions against this client.

        :param client_id_name:
        clientId in ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :return: client_id (uuid as string)
        """
        params_path = {"realm-name": self.realm_name, "clientId": client_id_name}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENTS.format(**params_path))
        data_content = raise_error_from_response(data_raw, KeycloakGetError)

        for client in data_content:
          client_id = json.dumps(client["clientId"]).strip('"')
          if client_id == client_id_name:
            return json.dumps(client["id"]).strip('"')

        return None

    def get_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :param client_id: id of client (not client-id)

        :return: ClientRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client(self, name, client_id, redirect_urls, protocol="openid-connect", public_client=True, direct_access_grants=True):
        """
        Create a client

        :param name: name of client, payload (ClientRepresentation)

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        """
        data={}
        data["name"]=name
        data["clientId"]=client_id
        data["redirectUris"]=redirect_urls
        data["protocol"]=protocol
        data["publicClient"]=public_client
        data["directAccessGrantsEnabled"]=direct_access_grants
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(URL_ADMIN_CLIENTS.format(**params_path),
                                            data=json.dumps(data))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201)

    def delete_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :param client_id: id of client (not client-id)

        :return: ClientRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def get_client_roles(self, client_id):
        """
        Get all roles for the client

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)

        :return: RoleRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id, role_name):
        """
        Get client role id
        This is required for further actions with this role.

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id), role_name: name of role

        :return: role_id
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path))
        data_content = raise_error_from_response(data_raw, KeycloakGetError)

        for role in data_content:
          this_role_name = json.dumps(role["name"]).strip('"')
          if this_role_name == role_name:
            return json.dumps(role["id"]).strip('"')

        return None

    def get_roles(self):
        """
        Get all roles for the realm or client

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :return: RoleRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_role(self, client_id, role_name):
        """
        Create a client role

        :param client_id: id of client (not client-id), payload (RoleRepresentation)

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        """
        data={}
        data["name"]=role_name
        data["clientRole"]=True
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_CLIENT_ROLES.format(**params_path),
                                            data=json.dumps(data))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201)

    def delete_client_role(self, client_id, role_name):
        """
        Create a client role

        :param client_id: id of client (not client-id), payload (RoleRepresentation)

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        """
        data={}
        data["name"]=role_name
        data["clientRole"]=True
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_CLIENT_ROLES.format(**params_path) + "/" + role_name,
                                            data=json.dumps(data))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def assign_client_role(self, user_id, client_id, role_id, role_name):
        """
        Assign a client role to a user

        :param client_id: id of client (not client-id), user_id: id of user, client_id: id of client containing role, role_id: client role id, role_name: client role name)

        """
        payload=[{}]
        payload[0]["id"]=role_id
        payload[0]["name"]=role_name

        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def sync_users(self, storage_id, action):
        data = {'action': action}
        params_path = {"realm-name": self.realm_name, "id": storage_id}
        params_query = {"action": action}
        data_raw = self.connection.raw_post(URL_ADMIN_USER_STORAGE.format(**params_path),
                                            data=json.dumps(data), **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)
