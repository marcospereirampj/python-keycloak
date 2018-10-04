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

# Unless otherwise stated in the comments, "id", in e.g. user_id, refers to the
# internal Keycloak server ID, usually a uuid string

import json

from .connection import ConnectionManager
from .exceptions import raise_error_from_response, KeycloakGetError
from .keycloak_openid import KeycloakOpenID
from .urls_patterns import URL_ADMIN_SERVER_INFO, URL_ADMIN_CLIENT_AUTHZ_RESOURCES, URL_ADMIN_CLIENT_ROLES, \
    URL_ADMIN_GET_SESSIONS, URL_ADMIN_RESET_PASSWORD, URL_ADMIN_SEND_UPDATE_ACCOUNT, \
    URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, URL_ADMIN_USER_GROUP, URL_ADMIN_REALM_ROLES, URL_ADMIN_GROUP_CHILD, \
    URL_ADMIN_USER_CONSENTS, URL_ADMIN_SEND_VERIFY_EMAIL, URL_ADMIN_CLIENT, URL_ADMIN_USER, URL_ADMIN_CLIENT_ROLE, \
    URL_ADMIN_USER_GROUPS, URL_ADMIN_CLIENTS, URL_ADMIN_FLOWS_EXECUTIONS, URL_ADMIN_GROUPS, URL_ADMIN_USER_CLIENT_ROLES, \
    URL_ADMIN_REALM_IMPORT, URL_ADMIN_USERS_COUNT, URL_ADMIN_FLOWS, URL_ADMIN_GROUP, URL_ADMIN_CLIENT_AUTHZ_SETTINGS, \
    URL_ADMIN_GROUP_MEMBERS, URL_ADMIN_USER_STORAGE, URL_ADMIN_GROUP_PERMISSIONS, URL_ADMIN_IDPS, \
    URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, URL_ADMIN_USERS


class KeycloakAdmin:

    def __init__(self, server_url, username, password, realm_name='master', client_id='admin-cli', verify=True):
        """

        :param server_url: Keycloak server url
        :param username: admin username
        :param password: admin password
        :param realm_name: realm name
        :param client_id: client id
        :param verify: True if want check connection SSL
        """
        self._username = username
        self._password = password
        self._client_id = client_id
        self._realm_name = realm_name

        # Get token Admin
        keycloak_openid = KeycloakOpenID(server_url=server_url, client_id=client_id, realm_name=realm_name,
                                         verify=verify)
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

    def import_realm(self, payload):
        """
        Import a new realm from a RealmRepresentation. Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/4.4/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation

        :return: RealmRepresentation
        """

        data_raw = self.connection.raw_post(URL_ADMIN_REALM_IMPORT,
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201)

    def get_users(self, query=None):
        """
        Get users Returns a list of users, filtered according to query parameters

        :return: users list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_USERS.format(**params_path), **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_idps(self):
        """
        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/3.3/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_IDPS.format(**params_path))
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

        exists = self.get_user_id(username=payload['username'])

        if exists is not None:
            return str(exists)

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

        UserRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation

        :return: user_id
        """

        users = self.get_users(query={"username": username})
        return next((user["id"] for user in users if user["username"] == username), None)

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

    def get_user_groups(self, user_id):
        """
        Get user groups Returns a list of groups of which the user is a member

        :param user_id: User id

        :return: user groups list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(URL_ADMIN_USER_GROUPS.format(**params_path))
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

    def set_user_password(self, user_id, password, temporary=True):
        """
        Set up a password for the user. If temporary is True, the user will have to reset
        the temporary password next time they log in.

        http://www.keycloak.org/docs-api/3.2/rest-api/#_users_resource
        http://www.keycloak.org/docs-api/3.2/rest-api/#_credentialrepresentation

        :param user_id: User id
        :param password: New password
        :param temporary: True if password is temporary

        :return:
        """
        payload = {"type": "password", "temporary": temporary, "value": password}
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(URL_ADMIN_RESET_PASSWORD.format(**params_path),
                                           data=json.dumps(payload))
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

        :param user_id:  id of user

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

    def get_groups(self):
        """
        Get groups belonging to the realm. Returns a list of groups belonging to the realm

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_grouprepresentation

        :return: array GroupRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_GROUPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_group(self, group_id):
        """
        Get group by id. Returns full group details

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_grouprepresentation

        :return: Keycloak server response (GroupRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_get(URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_subgroups(self, group, path):
        """
        Utility function to iterate through nested group structures

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_grouprepresentation

        :param name: group (GroupRepresentation)
        :param path: group path (string)

        :return: Keycloak server response (GroupRepresentation)
        """

        for subgroup in group["subGroups"]:
            if subgroup['path'] == path:
                return subgroup
            elif subgroup["subGroups"]:
                for subgroup in group["subGroups"]:
                    return self.get_subgroups(subgroup, path)
        return None

    def get_group_members(self, group_id, **query):
        """
        Get members by group id. Returns group members

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_userrepresentation

        :return: Keycloak server response (UserRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_get(URL_ADMIN_GROUP_MEMBERS.format(**params_path), **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_group_by_path(self, path, search_in_subgroups=False):
        """
        Get group id based on name or path.
        A straight name or path match with a top-level group will return first.
        Subgroups are traversed, the first to match path (or name with path) is returned.

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_grouprepresentation

        :param path: group path
        :param search_in_subgroups: True if want search in the subgroups
        :return: Keycloak server response (GroupRepresentation)
        """

        groups = self.get_groups()

        # TODO: Review this code is necessary
        for group in groups:
            if group['path'] == path:
                return group
            elif search_in_subgroups and group["subGroups"]:
                for group in group["subGroups"]:
                    if group['path'] == path:
                        return group
                    res = self.get_subgroups(group, path)
                    if res != None:
                        return res
        return None

    def create_group(self, payload, parent=None, skip_exists=False):
        """
        Creates a group in the Realm

        :param payload: GroupRepresentation
        :param parent: parent group's id. Required to create a sub-group.

        GroupRepresentation
        http://www.keycloak.org/docs-api/3.2/rest-api/#_grouprepresentation

        :return: Http response
        """
        name = payload['name']
        path = payload['path']
        exists = None

        if name is None and path is not None:
            path = "/" + name

        elif path is not None:
            exists = self.get_group_by_path(path=path, search_in_subgroups=True)

        if exists is not None:
            return str(exists)

        if parent is None:
            params_path = {"realm-name": self.realm_name}
            data_raw = self.connection.raw_post(URL_ADMIN_GROUPS.format(**params_path),
                                                data=json.dumps(payload))
        else:
            params_path = {"realm-name": self.realm_name, "id": parent, }
            data_raw = self.connection.raw_post(URL_ADMIN_GROUP_CHILD.format(**params_path),
                                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201, skip_exists=skip_exists)

    def group_set_permissions(self, group_id, enabled=True):
        """
        Enable/Disable permissions for a group. Cannot delete group if disabled

        :param group_id: id of group
        :param enabled: boolean
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_put(URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
                                           data=json.dumps({"enabled": enabled}))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def group_user_add(self, user_id, group_id):
        """
        Add user to group (user_id and group_id)

        :param group_id:  id of group
        :param user_id:  id of user
        :param group_id:  id of group to add to
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.connection.raw_put(URL_ADMIN_USER_GROUP.format(**params_path), data=None)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def group_user_remove(self, user_id, group_id):
        """
        Remove user from group (user_id and group_id)

        :param group_id:  id of group
        :param user_id:  id of user
        :param group_id:  id of group to add to
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_USER_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def delete_group(self, group_id):
        """
        Deletes a group in the Realm

        :param group_id:  id of group to delete
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def get_clients(self):
        """
        Get clients belonging to the realm Returns a list of clients belonging to the realm

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_id(self, client_name):
        """
        Get internal keycloak client id from client-id.
        This is required for further actions against this client.

        :param client_name: name in ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation
        :return: client_id (uuid as string)
        """

        clients = self.get_clients()

        for client in clients:
            if client_name == client.get('name') or client_name == client.get('clientId'):
                return client["id"]

        return None

    def get_client_authz_settings(self, client_id):
        """
        Get authorization json from client.

        :param client_id: id in ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path))
        return data_raw

    def get_client_authz_resources(self, client_id):
        """
        Get resources from client.

        :param client_id: id in ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path))
        return data_raw

    def create_client(self, payload, skip_exists=False):
        """
        Create a client

        ClientRepresentation: http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :param skip_exists: Skip if client already exist.
        :param payload: ClientRepresentation
        :return:  Keycloak server response (UserRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(URL_ADMIN_CLIENTS.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201, skip_exists=skip_exists)

    def delete_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def get_realm_roles(self):
        """
        Get all roles for the realm or client

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_roles(self, client_id):
        """
        Get all roles for the client

        :param client_id: id of client (not client-id)

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role(self, client_id, role_name):
        """
        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "role-name": role_name}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id, role_name):
        """
        Warning: Deprecated

        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        role = self.get_client_role(client_id, role_name)
        return role.get("id")

    def create_client_role(self, payload, skip_exists=False):
        """
        Create a client role

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :param payload: id of client (not client-id), role_name: name of role
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": self.client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_CLIENT_ROLES.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201, skip_exists=skip_exists)

    def delete_client_role(self, role_name):
        """
        Create a client role

        RoleRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_rolerepresentation

        :param role_name: role’s name (not id!)
        """
        params_path = {"realm-name": self.realm_name, "id": self.client_id, "role-name": role_name}
        data_raw = self.connection.raw_delete(URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def assign_client_role(self, user_id, client_id, roles):
        """
        Assign a client role to a user

        :param client_id: id of client (not client-id)
        :param user_id: id of user
        :param client_id: id of client containing role,
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def get_client_roles_of_user(self, user_id, client_id):
        """
        Get all client roles for a user.

        :param client_id: id of client (not client-id)
        :param user_id: id of user
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES, user_id, client_id)

    def get_available_client_roles_of_user(self, user_id, client_id):
        """
        Get available client role-mappings for a user.

        :param client_id: id of client (not client-id)
        :param user_id: id of user
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, user_id, client_id)

    def get_composite_client_roles_of_user(self, user_id, client_id):
        """
        Get composite client role-mappings for a user.

        :param client_id: id of client (not client-id)
        :param user_id: id of user
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, user_id, client_id)

    def _get_client_roles_of_user(self, client_level_role_mapping_url, user_id, client_id):
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_get(client_level_role_mapping_url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_roles_of_user(self, user_id, client_id, roles):
        """
        Delete client roles from a user.

        :param client_id: id of client (not client-id)
        :param user_id: id of user
        :param client_id: id of client containing role,
        :param roles: roles list or role to delete (use RoleRepresentation)
        :return: Keycloak server response
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                              data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def get_authentication_flows(self):
        """
        Get authentication flows. Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/4.1/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_ADMIN_FLOWS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow(self, payload, skip_exists=False):
        """
        Create a new authentication flow

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/4.1/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(URL_ADMIN_FLOWS.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201, skip_exists=skip_exists)

    def get_authentication_flow_executions(self, flow_alias):
        """
        Get authentication flow executions. Returns all execution steps

        :return: Response(json)
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_get(URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authentication_flow_executions(self, payload, flow_alias):
        """
        Update an authentication flow execution

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/4.1/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_put(URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
                                           data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def sync_users(self, storage_id, action):
        """
        Function to trigger user sync from provider

        :param storage_id:
        :param action:
        :return:
        """
        data = {'action': action}
        params_query = {"action": action}

        params_path = {"realm-name": self.realm_name, "id": storage_id}
        data_raw = self.connection.raw_post(URL_ADMIN_USER_STORAGE.format(**params_path),
                                            data=json.dumps(data), **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)
