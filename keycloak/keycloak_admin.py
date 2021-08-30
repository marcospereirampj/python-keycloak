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
from builtins import isinstance
from typing import Iterable

from .connection import ConnectionManager
from .exceptions import raise_error_from_response, KeycloakGetError
from .keycloak_openid import KeycloakOpenID
from .urls_patterns import URL_ADMIN_SERVER_INFO, URL_ADMIN_CLIENT_AUTHZ_RESOURCES, URL_ADMIN_CLIENT_ROLES, \
    URL_ADMIN_GET_SESSIONS, URL_ADMIN_RESET_PASSWORD, URL_ADMIN_SEND_UPDATE_ACCOUNT, URL_ADMIN_GROUPS_REALM_ROLES, \
    URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE, URL_ADMIN_CLIENT_INSTALLATION_PROVIDER, \
    URL_ADMIN_REALM_ROLES_ROLE_BY_NAME, URL_ADMIN_GROUPS_CLIENT_ROLES, \
    URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, URL_ADMIN_USER_GROUP, URL_ADMIN_REALM_ROLES, URL_ADMIN_GROUP_CHILD, \
    URL_ADMIN_USER_CONSENTS, URL_ADMIN_SEND_VERIFY_EMAIL, URL_ADMIN_CLIENT, URL_ADMIN_USER, URL_ADMIN_CLIENT_ROLE, \
    URL_ADMIN_USER_GROUPS, URL_ADMIN_CLIENTS, URL_ADMIN_FLOWS_EXECUTIONS, URL_ADMIN_GROUPS, URL_ADMIN_USER_CLIENT_ROLES, \
    URL_ADMIN_REALMS, URL_ADMIN_USERS_COUNT, URL_ADMIN_FLOWS, URL_ADMIN_GROUP, URL_ADMIN_CLIENT_AUTHZ_SETTINGS, \
    URL_ADMIN_GROUP_MEMBERS, URL_ADMIN_USER_STORAGE, URL_ADMIN_GROUP_PERMISSIONS, URL_ADMIN_IDPS, URL_ADMIN_IDP, \
    URL_ADMIN_IDP_MAPPERS, URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, URL_ADMIN_USERS, URL_ADMIN_CLIENT_SCOPES, \
    URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER, URL_ADMIN_CLIENT_SCOPE, URL_ADMIN_CLIENT_SECRETS, \
    URL_ADMIN_USER_REALM_ROLES, URL_ADMIN_REALM, URL_ADMIN_COMPONENTS, URL_ADMIN_COMPONENT, URL_ADMIN_KEYS, \
    URL_ADMIN_USER_FEDERATED_IDENTITY, URL_ADMIN_USER_FEDERATED_IDENTITIES, URL_ADMIN_CLIENT_ROLE_MEMBERS, \
    URL_ADMIN_REALM_ROLES_MEMBERS, URL_ADMIN_CLIENT_PROTOCOL_MAPPER, URL_ADMIN_CLIENT_SCOPES_MAPPERS, \
    URL_ADMIN_FLOWS_EXECUTIONS_EXEUCUTION, URL_ADMIN_FLOWS_EXECUTIONS_FLOW, URL_ADMIN_FLOWS_COPY, \
    URL_ADMIN_FLOWS_ALIAS, URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER, URL_ADMIN_AUTHENTICATOR_CONFIG, \
    URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE, URL_ADMIN_CLIENT_ALL_SESSIONS, URL_ADMIN_EVENTS, \
    URL_ADMIN_REALM_EXPORT, URL_ADMIN_DELETE_USER_ROLE, URL_ADMIN_USER_LOGOUT


class KeycloakAdmin:

    PAGE_SIZE = 100

    _server_url = None
    _username = None
    _password = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _auto_refresh_token = None
    _connection = None
    _token = None
    _custom_headers = None
    _user_realm_name = None

    def __init__(self, server_url, username=None, password=None, realm_name='master', client_id='admin-cli', verify=True,
                 client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None):
        """

        :param server_url: Keycloak server url
        :param username: admin username
        :param password: admin password
        :param realm_name: realm name
        :param client_id: client id
        :param verify: True if want check connection SSL
        :param client_secret_key: client secret key (optional, required only for access type confidential)
        :param custom_headers: dict of custom header to pass to each HTML request
        :param user_realm_name: The realm name of the user, if different from realm_name
        :param auto_refresh_token: list of methods that allows automatic token refresh. ex: ['get', 'put', 'post', 'delete']
        """
        self.server_url = server_url
        self.username = username
        self.password = password
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.auto_refresh_token = auto_refresh_token or []
        self.user_realm_name = user_realm_name
        self.custom_headers = custom_headers

        # Get token Admin
        self.get_token()

    @property
    def server_url(self):
        return self._server_url

    @server_url.setter
    def server_url(self, value):
        self._server_url = value

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
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value):
        self._verify = value

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

    @property
    def auto_refresh_token(self):
        return self._auto_refresh_token

    @property
    def user_realm_name(self):
        return self._user_realm_name

    @user_realm_name.setter
    def user_realm_name(self, value):
        self._user_realm_name = value

    @property
    def custom_headers(self):
        return self._custom_headers

    @custom_headers.setter
    def custom_headers(self, value):
        self._custom_headers = value

    @auto_refresh_token.setter
    def auto_refresh_token(self, value):
        allowed_methods = {'get', 'post', 'put', 'delete'}
        if not isinstance(value, Iterable):
            raise TypeError('Expected a list of strings among {allowed}'.format(allowed=allowed_methods))
        if not all(method in allowed_methods for method in value):
            raise TypeError('Unexpected method in auto_refresh_token, accepted methods are {allowed}'.format(allowed=allowed_methods))

        self._auto_refresh_token = value

    def __fetch_all(self, url, query=None):
        '''Wrapper function to paginate GET requests

        :param url: The url on which the query is executed
        :param query: Existing query parameters (optional)

        :return: Combined results of paginated queries
        '''
        results = []

        # initalize query if it was called with None
        if not query:
            query = {}
        page = 0
        query['max'] = self.PAGE_SIZE

        # fetch until we can
        while True:
            query['first'] = page*self.PAGE_SIZE
            partial_results = raise_error_from_response(
                self.raw_get(url, **query),
                KeycloakGetError)
            if not partial_results:
                break
            results.extend(partial_results)
            if len(partial_results) < query['max']:
                break
            page += 1
        return results

    def import_realm(self, payload):
        """
        Import a new realm from a RealmRepresentation. Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation

        :return: RealmRepresentation
        """

        data_raw = self.raw_post(URL_ADMIN_REALMS,
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def export_realm(self, export_clients=False, export_groups_and_role=False):
        """
        Export the realm configurations in the json format

        RealmRepresentation
        https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_partialexport

        :param export-clients: Skip if not want to export realm clients
        :param export-groups-and-roles: Skip if not want to export realm groups and roles
        
        :return: realm configurations JSON
        """
        params_path = {"realm-name": self.realm_name, "export-clients": export_clients, "export-groups-and-roles": export_groups_and_role }
        data_raw = self.raw_post(URL_ADMIN_REALM_EXPORT.format(**params_path), data="")
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realms(self):
        """
        Lists all realms in Keycloak deployment

        :return: realms list
        """
        data_raw = self.raw_get(URL_ADMIN_REALMS)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_realm(self, payload, skip_exists=False):
        """
        Create a realm

        RealmRepresentation:
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :param skip_exists: Skip if Realm already exist.
        :return:  Keycloak server response (RealmRepresentation)
        """

        data_raw = self.raw_post(URL_ADMIN_REALMS,
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_realm(self, realm_name, payload):
        """
        Update a realm. This wil only update top level attributes and will ignore any user,
        role, or client information in the payload.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :param payload: RealmRepresentation
        :return: Http response
        """

        params_path = {"realm-name": realm_name}
        data_raw = self.raw_put(URL_ADMIN_REALM.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_realm(self, realm_name):
        """
        Delete a realm

        :param realm_name: Realm name (not the realm id)
        :return: Http response
        """

        params_path = {"realm-name": realm_name}
        data_raw = self.raw_delete(URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_users(self, query=None):
        """
        Return a list of users, filtered according to query parameters

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param query: Query parameters (optional)
        :return: users list
        """
        params_path = {"realm-name": self.realm_name}
        return self.__fetch_all(URL_ADMIN_USERS.format(**params_path), query)

    def create_idp(self, payload):
        """
        Create an ID Provider,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityproviderrepresentation

        :param: payload: IdentityProviderRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(URL_ADMIN_IDPS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def add_mapper_to_idp(self, idp_alias, payload):
        """
        Create an ID Provider,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityprovidermapperrepresentation

        :param: idp_alias: alias for Idp to add mapper in
        :param: payload: IdentityProviderMapperRepresentation
        """
        params_path = {"realm-name": self.realm_name, "idp-alias": idp_alias}
        data_raw = self.raw_post(URL_ADMIN_IDP_MAPPERS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_idps(self):
        """
        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_IDPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_idp(self, idp_alias):
        """
        Deletes ID Provider,

        :param: idp_alias: idp alias name
        """
        params_path = {"realm-name": self.realm_name, "alias": idp_alias}
        data_raw = self.raw_delete(URL_ADMIN_IDP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_user(self, payload, exist_ok=True):
        """
        Create a new user. Username must be unique

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation
        :param exist_ok: If False, raise KeycloakGetError if username already exists. Otherwise, return existing user ID.

        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name}

        if exist_ok:
            exists = self.get_user_id(username=payload['username'])

            if exists is not None:
                return str(exists)

        data_raw = self.raw_post(URL_ADMIN_USERS.format(**params_path),
                                 data=json.dumps(payload))
        raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])
        _last_slash_idx = data_raw.headers['Location'].rindex('/')
        return data_raw.headers['Location'][_last_slash_idx + 1:]

    def users_count(self):
        """
        User counter

        :return: counter
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_USERS_COUNT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_id(self, username):
        """
        Get internal keycloak user id from username
        This is required for further actions against this user.

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation

        :return: user_id
        """
        lower_user_name = username.lower()
        users = self.get_users(query={"search": lower_user_name})
        return next((user["id"] for user in users if user["username"] == lower_user_name), None)

    def get_user(self, user_id):
        """
        Get representation of the user

        :param user_id: User id

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_groups(self, user_id):
        """
        Returns a list of groups of which the user is a member

        :param user_id: User id

        :return: user groups list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_USER_GROUPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_user(self, user_id, payload):
        """
        Update the user

        :param user_id: User id
        :param payload: UserRepresentation

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_put(URL_ADMIN_USER.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_user(self, user_id):
        """
        Delete the user

        :param user_id: User id

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_delete(URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def set_user_password(self, user_id, password, temporary=True):
        """
        Set up a password for the user. If temporary is True, the user will have to reset
        the temporary password next time they log in.

        https://www.keycloak.org/docs-api/8.0/rest-api/#_users_resource
        https://www.keycloak.org/docs-api/8.0/rest-api/#_credentialrepresentation

        :param user_id: User id
        :param password: New password
        :param temporary: True if password is temporary

        :return:
        """
        payload = {"type": "password", "temporary": temporary, "value": password}
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_put(URL_ADMIN_RESET_PASSWORD.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def logout(self, user_id):
        """
        Logs out user.

        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_logout

        :param user_id: User id
        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_post(URL_ADMIN_USER_LOGOUT.format(**params_path), data="")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def consents_user(self, user_id):
        """
        Get consents granted by the user

        :param user_id: User id

        :return: consents
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_USER_CONSENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_social_logins(self, user_id):
        """
        Returns a list of federated identities/social logins of which the user has been associated with
        :param user_id: User id
        :return: federated identities list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_USER_FEDERATED_IDENTITIES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_user_social_login(self, user_id, provider_id, provider_userid, provider_username):

        """
        Add a federated identity / social login provider to the user
        :param user_id: User id
        :param provider_id: Social login provider id
        :param provider_userid: userid specified by the provider
        :param provider_username: username specified by the provider
        :return:
        """
        payload = {"identityProvider": provider_id, "userId": provider_userid, "userName": provider_username}
        params_path = {"realm-name": self.realm_name, "id": user_id, "provider": provider_id}
        data_raw = self.raw_post(URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path), data=json.dumps(payload))

    def send_update_account(self, user_id, payload, client_id=None, lifespan=None, redirect_uri=None):
        """
        Send an update account email to the user. An email contains a
        link the user can click to perform a set of required actions.

        :param user_id: User id
        :param payload: A list of actions for the user to complete
        :param client_id: Client id (optional)
        :param lifespan: Number of seconds after which the generated token expires (optional)
        :param redirect_uri: The redirect uri (optional)

        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri}
        data_raw = self.raw_put(URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
                                data=json.dumps(payload), **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def send_verify_email(self, user_id, client_id=None, redirect_uri=None):
        """
        Send a update account email to the user An email contains a
        link the user can click to perform a set of required actions.

        :param user_id: User id
        :param client_id: Client id (optional)
        :param redirect_uri: Redirect uri (optional)

        :return:
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redirect_uri": redirect_uri}
        data_raw = self.raw_put(URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
                                data={}, **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_sessions(self, user_id):
        """
        Get sessions associated with the user

        :param user_id:  id of user

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_usersessionrepresentation

        :return: UserSessionRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_GET_SESSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_server_info(self):
        """
        Get themes, social providers, auth providers, and event listeners available on this server

        ServerInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        """
        data_raw = self.raw_get(URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_groups(self):
        """
        Returns a list of groups belonging to the realm

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: array GroupRepresentation
        """
        params_path = {"realm-name": self.realm_name}
        return self.__fetch_all(URL_ADMIN_GROUPS.format(**params_path))

    def get_group(self, group_id):
        """
        Get group by id. Returns full group details

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :param group_id: The group id
        :return: Keycloak server response (GroupRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_get(URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_subgroups(self, group, path):
        """
        Utility function to iterate through nested group structures

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :param name: group (GroupRepresentation)
        :param path: group path (string)

        :return: Keycloak server response (GroupRepresentation)
        """

        for subgroup in group["subGroups"]:
            if subgroup['path'] == path:
                return subgroup
            elif subgroup["subGroups"]:
                for subgroup in group["subGroups"]:
                    result = self.get_subgroups(subgroup, path)
                    if result:
                        return result
        # went through the tree without hits
        return None

    def get_group_members(self, group_id, **query):
        """
        Get members by group id. Returns group members

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_userrepresentation

        :param group_id: The group id
        :param query: Additional query parameters (see https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getmembers)
        :return: Keycloak server response (UserRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        return self.__fetch_all(URL_ADMIN_GROUP_MEMBERS.format(**params_path), query)

    def get_group_by_path(self, path, search_in_subgroups=False):
        """
        Get group id based on name or path.
        A straight name or path match with a top-level group will return first.
        Subgroups are traversed, the first to match path (or name with path) is returned.

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

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
        :param skip_exists: If true then do not raise an error if it already exists

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: Http response
        """

        if parent is None:
            params_path = {"realm-name": self.realm_name}
            data_raw = self.raw_post(URL_ADMIN_GROUPS.format(**params_path),
                                     data=json.dumps(payload))
        else:
            params_path = {"realm-name": self.realm_name, "id": parent, }
            data_raw = self.raw_post(URL_ADMIN_GROUP_CHILD.format(**params_path),
                                     data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_group(self, group_id, payload):
        """
        Update group, ignores subgroups.

        :param group_id: id of group
        :param payload: GroupRepresentation with updated information.

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: Http response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_put(URL_ADMIN_GROUP.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def group_set_permissions(self, group_id, enabled=True):
        """
        Enable/Disable permissions for a group. Cannot delete group if disabled

        :param group_id: id of group
        :param enabled: boolean
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_put(URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
                                data=json.dumps({"enabled": enabled}))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def group_user_add(self, user_id, group_id):
        """
        Add user to group (user_id and group_id)

        :param user_id:  id of user
        :param group_id:  id of group to add to
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.raw_put(URL_ADMIN_USER_GROUP.format(**params_path), data=None)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def group_user_remove(self, user_id, group_id):
        """
        Remove user from group (user_id and group_id)

        :param user_id:  id of user
        :param group_id:  id of group to remove from
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.raw_delete(URL_ADMIN_USER_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_group(self, group_id):
        """
        Deletes a group in the Realm

        :param group_id:  id of group to delete
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_delete(URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_clients(self):
        """
        Returns a list of clients belonging to the realm

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_id(self, client_name):
        """
        Get internal keycloak client id from client-id.
        This is required for further actions against this client.

        :param client_name: name in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
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
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path))
        return data_raw

    def get_client_authz_resources(self, client_id):
        """
        Get resources from client.

        :param client_id: id in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path))
        return data_raw

    def get_client_service_account_user(self, client_id):
        """
        Get service account user from client.

        :param client_id: id in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: UserRepresentation
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client(self, payload, skip_exists=False):
        """
        Create a client

        ClientRepresentation: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param skip_exists: If true then do not raise an error if client already exists
        :param payload: ClientRepresentation
        :return:  Keycloak server response (UserRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(URL_ADMIN_CLIENTS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_client(self, client_id, payload):
        """
        Update a client

        :param client_id: Client id
        :param payload: ClientRepresentation

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_put(URL_ADMIN_CLIENT.format(**params_path),
                                           data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_client_installation_provider(self, client_id, provider_id):
        """
        Get content for given installation provider

        Related documentation:
        https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_clients_resource

        Possible provider_id list available in the ServerInfoRepresentation#clientInstallations
        https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_serverinforepresentation

        :param client_id: Client id
        :param provider_id: provider id to specify response format
        """

        params_path = {"realm-name": self.realm_name, "id": client_id, "provider-id": provider_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_INSTALLATION_PROVIDER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def get_realm_roles(self):
        """
        Get all roles for the realm or client

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realm_role_members(self, role_name, **query):
        """
        Get role members of realm by role name.
        :param role_name: Name of the role.
        :param query: Additional Query parameters (see https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_roles_resource)
        :return: Keycloak Server Response (UserRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "role-name":role_name}
        return self.__fetch_all(URL_ADMIN_REALM_ROLES_MEMBERS.format(**params_path), query)

    def get_client_roles(self, client_id):
        """
        Get all roles for the client

        :param client_id: id of client (not client-id)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role(self, client_id, role_name):
        """
        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "role-name": role_name}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id, role_name):
        """
        Warning: Deprecated

        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        role = self.get_client_role(client_id, role_name)
        return role.get("id")

    def create_client_role(self, client_role_id, payload, skip_exists=False):
        """
        Create a client role

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :param payload: RoleRepresentation
        :param skip_exists: If true then do not raise an error if client role already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_role_id}
        data_raw = self.raw_post(URL_ADMIN_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def add_composite_client_roles_to_role(self, client_role_id, role_name, roles):
        """
        Add composite roles to client role

        :param client_role_id: id of client (not client-id)
        :param role_name: The name of the role
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.raw_post(URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_client_role(self, client_role_id, role_name):
        """
        Delete a client role

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :param role_name: role’s name (not id!)
        """
        params_path = {"realm-name": self.realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.raw_delete(URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def assign_client_role(self, user_id, client_id, roles):
        """
        Assign a client role to a user

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_post(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_client_role_members(self, client_id, role_name, **query):
        """
        Get members by client role .
        :param client_id: The client id
        :param role_name: the name of role to be queried.
        :param query: Additional query parameters ( see https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_clients_resource)
        :return: Keycloak server response (UserRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id":client_id, "role-name":role_name}
        return self.__fetch_all(URL_ADMIN_CLIENT_ROLE_MEMBERS.format(**params_path) , query)


    def create_realm_role(self, payload, skip_exists=False):
        """
        Create a new role for the realm or client

        :param payload: The role (use RoleRepresentation)
        :param skip_exists: If true then do not raise an error if realm role already exists
        :return Keycloak server response
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(URL_ADMIN_REALM_ROLES.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def get_realm_role(self, role_name):
        """
        Get realm role by role name
        :param role_name: role's name, not id!

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation
        :return: role_id
        """
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.raw_get(URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_realm_role(self, role_name, payload):
        """
        Update a role for the realm by name
        :param role_name: The name of the role to be updated
        :param payload: The role (use RoleRepresentation)
        :return Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_put(URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
                                            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_realm_role(self, role_name):
        """
        Delete a role for the realm by name
        :param payload: The role name {'role-name':'name-of-the-role'}
        :return Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def add_composite_realm_roles_to_role(self, role_name, roles):
        """
        Add composite roles to the role

        :param role_name: The name of the role
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.raw_post(
            URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError,
                                         expected_codes=[204])

    def remove_composite_realm_roles_to_role(self, role_name, roles):
        """
        Remove composite roles from the role

        :param role_name: The name of the role
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.raw_delete(
            URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError,
                                         expected_codes=[204])

    def get_composite_realm_roles_of_role(self, role_name):
        """
        Get composite roles of the role

        :param role_name: The name of the role
        :return Keycloak server response (array RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.raw_get(
            URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles(self, user_id, roles):
        """
        Assign realm roles to a user

        :param user_id: id of user
        :param client_id: id of client containing role (not client-id)
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_post(URL_ADMIN_USER_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_realm_roles_of_user(self, user_id):
        """
        Get all realm roles for a user.

        :param user_id: id of user
        :return: Keycloak server response (array RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.raw_get(URL_ADMIN_USER_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_realm_roles(self, group_id, roles):
        """
        Assign realm roles to a group

        :param group_id: id of groupp
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_post(URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_group_realm_roles(self, group_id, roles):
        """
        Delete realm roles of a group

        :param group_id: id of group
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_delete(URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_group_realm_roles(self, group_id):
        """
        Get all realm roles for a group.

        :param user_id: id of the group
        :return: Keycloak server response (array RoleRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.raw_get(URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_client_roles(self, group_id, client_id, roles):
        """
        Assign client roles to a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_post(URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_group_client_roles(self, group_id, client_id):
        """
        Get client roles of a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :return Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_get(URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_group_client_roles(self, group_id, client_id, roles):
        """
        Delete client roles of a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response (array RoleRepresentation)
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_client_roles_of_user(self, user_id, client_id):
        """
        Get all client roles for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES, user_id, client_id)

    def get_available_client_roles_of_user(self, user_id, client_id):
        """
        Get available client role-mappings for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, user_id, client_id)

    def get_composite_client_roles_of_user(self, user_id, client_id):
        """
        Get composite client role-mappings for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, user_id, client_id)

    def _get_client_roles_of_user(self, client_level_role_mapping_url, user_id, client_id):
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_get(client_level_role_mapping_url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_roles_of_user(self, user_id, client_id, roles):
        """
        Delete client roles from a user.

        :param user_id: id of user
        :param client_id: id of client containing role (not client-id)
        :param roles: roles list or role to delete (use RoleRepresentation)
        :return: Keycloak server response
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                   data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_authentication_flows(self):
        """
        Get authentication flows. Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_FLOWS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authentication_flow_for_id(self, flow_id):
        """
        Get one authentication flow by it's id/alias. Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: the id of a flow NOT it's alias
        :return: Keycloak server response (AuthenticationFlowRepresentation)
        """
        params_path = {"realm-name": self.realm_name, "flow-id": flow_id}
        data_raw = self.raw_get(URL_ADMIN_FLOWS_ALIAS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow(self, payload, skip_exists=False):
        """
        Create a new authentication flow

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :param skip_exists: If true then do not raise an error if authentication flow already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(URL_ADMIN_FLOWS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def copy_authentication_flow(self, payload, flow_alias):
        """
        Copy existing authentication flow under a new name. The new name is given as 'newName' attribute of the passed payload.

        :param payload: JSON containing 'newName' attribute
        :param flow_alias: the flow alias
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(URL_ADMIN_FLOWS_COPY.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_authentication_flow_executions(self, flow_alias):
        """
        Get authentication flow executions. Returns all execution steps

        :param flow_alias: the flow alias
        :return: Response(json)
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_get(URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authentication_flow_executions(self, payload, flow_alias):
        """
        Update an authentication flow execution

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :param flow_alias: The flow alias
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_put(URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_authentication_flow_execution(self, payload, flow_alias):
        """
        Create an authentication flow execution

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :param flow_alias: The flow alias
        :return: Keycloak server response
        """

        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(URL_ADMIN_FLOWS_EXECUTIONS_EXEUCUTION.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def create_authentication_flow_subflow(self, payload, flow_alias, skip_exists=False):
        """
        Create a new sub authentication flow for a given authentication flow

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :param flow_alias: The flow alias
        :param skip_exists: If true then do not raise an error if authentication flow already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(URL_ADMIN_FLOWS_EXECUTIONS_FLOW.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def get_authenticator_config(self, config_id):
        """
        Get authenticator configuration. Returns all configuration details.

        :param config_id: Authenticator config id
        :return: Response(json)
        """
        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.raw_get(URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authenticator_config(self, payload, config_id):
        """
        Update an authenticator configuration.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticatorconfigrepresentation

        :param payload: AuthenticatorConfigRepresentation
        :param config_id: Authenticator config id
        :return: Response(json)
        """
        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.raw_put(URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_authenticator_config(self, config_id):
        """
        Delete a authenticator configuration.
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authentication_management_resource

        :param config_id: Authenticator config id
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.raw_delete(URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def sync_users(self, storage_id, action):
        """
        Function to trigger user sync from provider

        :param storage_id: The id of the user storage provider
        :param action: Action can be "triggerFullSync" or "triggerChangedUsersSync"
        :return:
        """
        data = {'action': action}
        params_query = {"action": action}

        params_path = {"realm-name": self.realm_name, "id": storage_id}
        data_raw = self.raw_post(URL_ADMIN_USER_STORAGE.format(**params_path),
                                 data=json.dumps(data), **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scopes(self):
        """
        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :return: Keycloak server response Array of (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_SCOPES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope(self, client_scope_id):
        """
        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :param client_scope_id: The id of the client scope
        :return: Keycloak server response (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_SCOPE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_scope(self, payload, skip_exists=False):
        """
        Create a client scope

        ClientScopeRepresentation: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :param payload: ClientScopeRepresentation
        :param skip_exists: If true then do not raise an error if client scope already exists
        :return:  Keycloak server response (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(URL_ADMIN_CLIENT_SCOPES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_client_scope(self, client_scope_id, payload):
        """
        Update a client scope

        ClientScopeRepresentation: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :param payload: ClientScopeRepresentation
        :return:  Keycloak server response (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.raw_put(URL_ADMIN_CLIENT_SCOPE.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def add_mapper_to_client_scope(self, client_scope_id, payload):
        """
        Add a mapper to a client scope
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_create_mapper

        :param client_scope_id: The id of the client scope
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}

        data_raw = self.raw_post(
            URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path), data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def delete_mapper_from_client_scope(self, client_scope_id, protocol_mppaer_id):
        """
        Delete a mapper from a client scope
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_delete_mapper

        :param client_scope_id: The id of the client scope
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id,
                       "protocol-mapper-id": protocol_mppaer_id}

        data_raw = self.raw_delete(
            URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def update_mapper_in_client_scope(self, client_scope_id, protocol_mapper_id, payload):
        """
        Update an existing protocol mapper in a client scope
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_protocol_mappers_resource

        :param client_scope_id: The id of the client scope
        :param protocol_mapper_id: The id of the protocol mapper which exists in the client scope
               and should to be updated
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id,
                       "protocol-mapper-id": protocol_mapper_id}

        data_raw = self.raw_put(
            URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path), data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def add_mapper_to_client(self, client_id, payload):
        """
        Add a mapper to a client
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_create_mapper

        :param client_id: The id of the client
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.raw_post(
            URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path), data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def generate_client_secrets(self, client_id):
        """

        Generate a new secret for the client
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_regeneratesecret

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(URL_ADMIN_CLIENT_SECRETS.format(**params_path), data=None)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_secrets(self, client_id):
        """

        Get representation of the client secrets
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientsecret

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_SECRETS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_components(self, query=None):
        """
        Return a list of components, filtered according to query parameters

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :param query: Query parameters (optional)
        :return: components list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_COMPONENTS.format(**params_path),
                                data=None, **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_component(self, payload):
        """
        Create a new component.

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :param payload: ComponentRepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name}

        data_raw = self.raw_post(URL_ADMIN_COMPONENTS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_component(self, component_id):
        """
        Get representation of the component

        :param component_id: Component id

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :return: ComponentRepresentation
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.raw_get(URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_component(self, component_id, payload):
        """
        Update the component

        :param component_id: Component id
        :param payload: ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.raw_put(URL_ADMIN_COMPONENT.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_component(self, component_id):
        """
        Delete the component

        :param component_id: Component id

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.raw_delete(URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_keys(self):
        """
        Return a list of keys, filtered according to query parameters

        KeysMetadataRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_key_resource

        :return: keys list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_KEYS.format(**params_path),
                                data=None)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_events(self, query=None):
        """
        Return a list of events, filtered according to query parameters

        EventRepresentation array
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_eventrepresentation

        :return: events list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_get(URL_ADMIN_EVENTS.format(**params_path),
                                data=None, **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def set_events(self, payload):
        """
        Set realm events configuration

        RealmEventsConfigRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmeventsconfigrepresentation

        :return: Http response
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_put(URL_ADMIN_EVENTS.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def raw_get(self, *args, **kwargs):
        """
        Calls connection.raw_get.

        If auto_refresh is set for *get* and *access_token* is expired, it will refresh the token
        and try *get* once more.
        """
        r = self.connection.raw_get(*args, **kwargs)
        if 'get' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self.connection.raw_get(*args, **kwargs)
        return r

    def raw_post(self, *args, **kwargs):
        """
        Calls connection.raw_post.

        If auto_refresh is set for *post* and *access_token* is expired, it will refresh the token
        and try *post* once more.
        """
        r = self.connection.raw_post(*args, **kwargs)
        if 'post' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self.connection.raw_post(*args, **kwargs)
        return r

    def raw_put(self, *args, **kwargs):
        """
        Calls connection.raw_put.

        If auto_refresh is set for *put* and *access_token* is expired, it will refresh the token
        and try *put* once more.
        """
        r = self.connection.raw_put(*args, **kwargs)
        if 'put' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self.connection.raw_put(*args, **kwargs)
        return r

    def raw_delete(self, *args, **kwargs):
        """
        Calls connection.raw_delete.

        If auto_refresh is set for *delete* and *access_token* is expired, it will refresh the token
        and try *delete* once more.
        """
        r = self.connection.raw_delete(*args, **kwargs)
        if 'delete' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self.connection.raw_delete(*args, **kwargs)
        return r

    def get_token(self):
        token_realm_name = 'master' if self.client_secret_key else self.user_realm_name or self.realm_name
        self.keycloak_openid = KeycloakOpenID(server_url=self.server_url, client_id=self.client_id,
                                              realm_name=token_realm_name, verify=self.verify,
                                              client_secret_key=self.client_secret_key,
                                              custom_headers=self.custom_headers)

        grant_type = ["password"]
        if self.client_secret_key:
            grant_type = ["client_credentials"]
            if self.user_realm_name:
                self.realm_name = self.user_realm_name

        self._token = self.keycloak_openid.token(self.username, self.password, grant_type=grant_type)

        headers = {
            'Authorization': 'Bearer ' + self.token.get('access_token'),
            'Content-Type': 'application/json'
        }

        if self.custom_headers is not None:
            # merge custom headers to main headers
            headers.update(self.custom_headers)

        self._connection = ConnectionManager(base_url=self.server_url,
                                             headers=headers,
                                             timeout=60,
                                             verify=self.verify)

    def refresh_token(self):
        refresh_token = self.token.get('refresh_token')
        try:
            self.token = self.keycloak_openid.refresh_token(refresh_token)
        except KeycloakGetError as e:
            if e.response_code == 400 and (b'Refresh token expired' in e.response_body or
                                           b'Token is not active' in e.response_body):
                self.get_token()
            else:
                raise
        self.connection.add_param_headers('Authorization', 'Bearer ' + self.token.get('access_token'))

    def get_client_all_sessions(self, client_id):
        """
        Get sessions associated with the client

        :param client_id:  id of client

        UserSessionRepresentation
        http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_usersessionrepresentation

        :return: UserSessionRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ALL_SESSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)


    def delete_user_realm_role(self, user_id, payload):
        """
        Delete realm-level role mappings
        DELETE admin/realms/{realm-name}/users/{id}/role-mappings/realm

        """
        params_path = {"realm-name": self.realm_name, "id": str(user_id) }
        data_raw = self.connection.raw_delete(URL_ADMIN_DELETE_USER_ROLE.format(**params_path),
                                              data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])