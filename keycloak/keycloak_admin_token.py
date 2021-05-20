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
from .keycloak_admin import KeycloakAdmin
from .connection import ConnectionManager
from .exceptions import raise_error_from_response, KeycloakGetError
from .keycloak_openid import KeycloakOpenID
from .urls_patterns import URL_ADMIN_SERVER_INFO, URL_ADMIN_CLIENT_AUTHZ_RESOURCES, URL_ADMIN_CLIENT_ROLES, \
    URL_ADMIN_GET_SESSIONS, URL_ADMIN_RESET_PASSWORD, URL_ADMIN_SEND_UPDATE_ACCOUNT, URL_ADMIN_GROUPS_REALM_ROLES,\
    URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE, URL_ADMIN_CLIENT_INSTALLATION_PROVIDER, \
    URL_ADMIN_REALM_ROLES_ROLE_BY_NAME, URL_ADMIN_GET_GROUPS_REALM_ROLES, URL_ADMIN_GROUPS_CLIENT_ROLES, \
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
    URL_ADMIN_FLOWS_ALIAS, URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER


class KeycloakAdminToken(KeycloakAdmin):

    PAGE_SIZE = 100

    _server_url = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _auto_refresh_token = None
    _connection = None
    _token = None
    _custom_headers = None
    _user_realm_name = None

    def __init__(self, server_url, realm_name='master', client_id='admin-cli', verify=True,
                 client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None, token= None):
        """

        :param server_url: Keycloak server url
        :param realm_name: realm name
        :param client_id: client id
        :param verify: True if want check connection SSL
        :param client_secret_key: client secret key
        :param custom_headers: dict of custom header to pass to each HTML request
        :param user_realm_name: The realm name of the user, if different from realm_name
        :param auto_refresh_token: list of methods that allows automatic token refresh. ex: ['get', 'put', 'post', 'delete']
        """
        self.server_url = server_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.auto_refresh_token = auto_refresh_token or []
        self.user_realm_name = user_realm_name
        self.custom_headers = custom_headers
        self.token = token
        # set token Admin
        self.set_token()
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

    def set_token(self):
        self.keycloak_openid = KeycloakOpenID(server_url=self.server_url, client_id=self.client_id,
                                              realm_name=self.user_realm_name or self.realm_name, verify=self.verify,
                                              client_secret_key=self.client_secret_key,
                                              custom_headers=self.custom_headers)

        grant_type = ["token"]
        if self.client_secret_key:
            grant_type = ["client_credentials"]

        self._token = self.token

        headers = {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json'
        }
         #print('',headers)
        if self.custom_headers is not None:
            # merge custom headers to main headers
            headers.update(self.custom_headers)

        self._connection = ConnectionManager(base_url=self.server_url,
                                             headers=headers,
                                             timeout=60,
                                             verify=self.verify)
