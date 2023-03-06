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

"""The keycloak admin module."""

import copy
import json
from builtins import isinstance

import deprecation
from requests_toolbelt import MultipartEncoder

from . import urls_patterns
from ._version import __version__
from .exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    raise_error_from_response,
)
from .openid_connection import KeycloakOpenIDConnection


class KeycloakAdmin:
    """Keycloak Admin client.

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
    :param auto_refresh_token: list of methods that allows automatic token refresh.
        Ex: ['get', 'put', 'post', 'delete']
    :type auto_refresh_token: list
    :param timeout: connection timeout in seconds
    :type timeout: int
    :param connection: A KeycloakOpenIDConnection as an alternative to individual params.
    :type connection: KeycloakOpenIDConnection
    """

    PAGE_SIZE = 100

    _auto_refresh_token = None
    _connection = None

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
        auto_refresh_token=None,
        timeout=60,
        connection: KeycloakOpenIDConnection = None,
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
        :param auto_refresh_token: list of methods that allows automatic token refresh.
            Ex: ['get', 'put', 'post', 'delete']
        :type auto_refresh_token: list
        :param timeout: connection timeout in seconds
        :type timeout: int
        :param connection: An OpenID Connection as an alternative to individual params.
        :type connection: KeycloakOpenIDConnection
        """
        self.connection = connection or KeycloakOpenIDConnection(
            server_url=server_url,
            username=username,
            password=password,
            token=token,
            totp=totp,
            realm_name=realm_name,
            client_id=client_id,
            verify=verify,
            client_secret_key=client_secret_key,
            user_realm_name=user_realm_name,
            custom_headers=custom_headers,
            timeout=timeout,
        )
        self.auto_refresh_token = auto_refresh_token

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.server_url property instead",
    )
    def server_url(self):
        """Get server url.

        :returns: Keycloak server url
        :rtype: str
        """
        return self.connection.server_url

    @server_url.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.server_url property instead",
    )
    def server_url(self, value):
        self.connection.server_url = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.realm_name property instead",
    )
    def realm_name(self):
        """Get realm name.

        :returns: Realm name
        :rtype: str
        """
        return self.connection.realm_name

    @realm_name.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.realm_name property instead",
    )
    def realm_name(self, value):
        self.connection.realm_name = value

    @property
    def connection(self):
        """Get connection.

        :returns: Connection manager
        :rtype: KeycloakOpenIDConnection
        """
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.client_id property instead",
    )
    def client_id(self):
        """Get client id.

        :returns: Client id
        :rtype: str
        """
        return self.connection.client_id

    @client_id.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.client_id property instead",
    )
    def client_id(self, value):
        self.connection.client_id = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.client_secret_key property instead",
    )
    def client_secret_key(self):
        """Get client secret key.

        :returns: Client secret key
        :rtype: str
        """
        return self.connection.client_secret_key

    @client_secret_key.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.client_secret_key property instead",
    )
    def client_secret_key(self, value):
        self.connection.client_secret_key = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.verify property instead",
    )
    def verify(self):
        """Get verify.

        :returns: Verify indicator
        :rtype: bool
        """
        return self.connection.verify

    @verify.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.verify property instead",
    )
    def verify(self, value):
        self.connection.verify = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.username property instead",
    )
    def username(self):
        """Get username.

        :returns: Admin username
        :rtype: str
        """
        return self.connection.username

    @username.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.username property instead",
    )
    def username(self, value):
        self.connection.username = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.password property instead",
    )
    def password(self):
        """Get password.

        :returns: Admin password
        :rtype: str
        """
        return self.connection.password

    @password.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.password property instead",
    )
    def password(self, value):
        self.connection.password = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.totp property instead",
    )
    def totp(self):
        """Get totp.

        :returns: TOTP
        :rtype: str
        """
        return self.connection.totp

    @totp.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.totp property instead",
    )
    def totp(self, value):
        self.connection.totp = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.token property instead",
    )
    def token(self):
        """Get token.

        :returns: Access and refresh token
        :rtype: dict
        """
        return self.connection.token

    @token.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.token property instead",
    )
    def token(self, value):
        self.connection.token = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.user_realm_name property instead",
    )
    def user_realm_name(self):
        """Get user realm name.

        :returns: User realm name
        :rtype: str
        """
        return self.connection.user_realm_name

    @user_realm_name.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.user_realm_name property instead",
    )
    def user_realm_name(self, value):
        self.connection.user_realm_name = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.custom_headers property instead",
    )
    def custom_headers(self):
        """Get custom headers.

        :returns: Custom headers
        :rtype: dict
        """
        return self.connection.custom_headers

    @custom_headers.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.custom_headers property instead",
    )
    def custom_headers(self, value):
        self.connection.custom_headers = value

    @property
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Auto-refresh will be implicitly set for all requests",
    )
    def auto_refresh_token(self):
        """Get auto refresh token.

        :returns: List of methods for automatic token refresh
        :rtype: list
        """
        return self._auto_refresh_token

    @auto_refresh_token.setter
    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Auto-refresh will be implicitly set for all requests",
    )
    def auto_refresh_token(self, value):
        self._auto_refresh_token = value or []

    def __fetch_all(self, url, query=None):
        """Paginate over get requests.

        Wrapper function to paginate GET requests.

        :param url: The url on which the query is executed
        :type url: str
        :param query: Existing query parameters (optional)
        :type query: dict

        :return: Combined results of paginated queries
        :rtype: list
        """
        results = []

        # initialize query if it was called with None
        if not query:
            query = {}
        page = 0
        query["max"] = self.PAGE_SIZE

        # fetch until we can
        while True:
            query["first"] = page * self.PAGE_SIZE
            partial_results = raise_error_from_response(
                self.connection.raw_get(url, **query), KeycloakGetError
            )
            if not partial_results:
                break
            results.extend(partial_results)
            if len(partial_results) < query["max"]:
                break
            page += 1
        return results

    def __fetch_paginated(self, url, query=None):
        """Make a specific paginated request.

        :param url: The url on which the query is executed
        :type url: str
        :param query: Pagination settings
        :type query: dict
        :returns: Response
        :rtype: dict
        """
        query = query or {}
        return raise_error_from_response(self.connection.raw_get(url, **query), KeycloakGetError)

    def import_realm(self, payload):
        """Import a new realm from a RealmRepresentation.

        Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :return: RealmRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALMS, data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def export_realm(self, export_clients=False, export_groups_and_role=False):
        """Export the realm configurations in the json format.

        RealmRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_partialexport

        :param export_clients: Skip if not want to export realm clients
        :type export_clients: bool
        :param export_groups_and_role: Skip if not want to export realm groups and roles
        :type export_groups_and_role: bool

        :return: realm configurations JSON
        :rtype: dict
        """
        params_path = {
            "realm-name": self.realm_name,
            "export-clients": export_clients,
            "export-groups-and-roles": export_groups_and_role,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_EXPORT.format(**params_path), data=""
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_realms(self):
        """List all realms in Keycloak deployment.

        :return: realms list
        :rtype: list
        """
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_REALMS)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realm(self, realm_name):
        """Get a specific realm.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: RealmRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def create_realm(self, payload, skip_exists=False):
        """Create a realm.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :param skip_exists: Skip if Realm already exist.
        :type skip_exists: bool
        :return: Keycloak server response (RealmRepresentation)
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALMS, data=json.dumps(payload)
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def update_realm(self, realm_name, payload):
        """Update a realm.

        This will only update top level attributes and will ignore any user,
        role, or client information in the payload.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: RealmRepresentation
        :type payload: dict
        :return: Http response
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_realm(self, realm_name):
        """Delete a realm.

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: Http response
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_users(self, query=None):
        """Get all users.

        Return a list of users, filtered according to query parameters

        UserRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_userrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: users list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.realm_name}
        url = urls_patterns.URL_ADMIN_USERS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def create_idp(self, payload):
        """Create an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_identityproviderrepresentation

        :param: payload: IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_IDPS.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def update_idp(self, idp_alias, payload):
        """Update an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/15.0/rest-api/index.html#_identity_providers_resource

        :param: idp_alias: alias for IdP to update
        :type idp_alias: str
        :param: payload: The IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "alias": idp_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_IDP.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def add_mapper_to_idp(self, idp_alias, payload):
        """Create an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_identityprovidermapperrepresentation

        :param: idp_alias: alias for Idp to add mapper in
        :type idp_alias: str
        :param: payload: IdentityProviderMapperRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "idp-alias": idp_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def update_mapper_in_idp(self, idp_alias, mapper_id, payload):
        """Update an IdP mapper.

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_update

        :param: idp_alias: alias for Idp to fetch mappers
        :type idp_alias: str
        :param: mapper_id: Mapper Id to update
        :type mapper_id: str
        :param: payload: IdentityProviderMapperRepresentation
        :type payload: dict
        :return: Http response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.realm_name,
            "idp-alias": idp_alias,
            "mapper-id": mapper_id,
        }

        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_IDP_MAPPER_UPDATE.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def get_idp_mappers(self, idp_alias):
        """Get IDP mappers.

        Returns a list of ID Providers mappers

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getmappers

        :param: idp_alias: alias for Idp to fetch mappers
        :type idp_alias: str
        :return: array IdentityProviderMapperRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "idp-alias": idp_alias}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_idps(self):
        """Get IDPs.

        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_IDPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_idp(self, idp_alias):
        """Delete an ID Provider.

        :param: idp_alias: idp alias name
        :type idp_alias: str
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "alias": idp_alias}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_IDP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def create_user(self, payload, exist_ok=False):
        """Create a new user.

        Username must be unique

        UserRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation
        :type payload: dict
        :param exist_ok: If False, raise KeycloakGetError if username already exists.
            Otherwise, return existing user ID.
        :type exist_ok: bool

        :return: UserRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}

        if exist_ok:
            exists = self.get_user_id(username=payload["username"])

            if exists is not None:
                return str(exists)

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USERS.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def users_count(self, query=None):
        """Count users.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_users_resource

        :param query: (dict) Query parameters for users count
        :type query: dict

        :return: counter
        :rtype: int
        """
        query = query or dict()
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USERS_COUNT.format(**params_path), **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_id(self, username):
        """Get internal keycloak user id from username.

        This is required for further actions against this user.

        UserRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation
        :type username: str

        :return: user_id
        :rtype: str
        """
        lower_user_name = username.lower()
        users = self.get_users(query={"search": lower_user_name})
        return next((user["id"] for user in users if user["username"] == lower_user_name), None)

    def get_user(self, user_id):
        """Get representation of the user.

        UserRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_userrepresentation

        :param user_id: User id
        :type user_id: str
        :return: UserRepresentation
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_groups(self, user_id, brief_representation=True):
        """Get user groups.

        Returns a list of groups of which the user is a member

        :param user_id: User id
        :type user_id: str
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: user groups list
        :rtype: list
        """
        params = {"briefRepresentation": brief_representation}
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_GROUPS.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_user(self, user_id, payload):
        """Update the user.

        :param user_id: User id
        :type user_id: str
        :param payload: UserRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_USER.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def disable_user(self, user_id):
        """Disable the user from the realm. Disabled users can not log in.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return self.update_user(user_id=user_id, payload={"enabled": False})

    def enable_user(self, user_id):
        """Enable the user from the realm.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return self.update_user(user_id=user_id, payload={"enabled": True})

    def disable_all_users(self):
        """Disable all existing users."""
        users = self.get_users()
        for user in users:
            user_id = user["id"]
            self.disable_user(user_id=user_id)

    def enable_all_users(self):
        """Disable all existing users."""
        users = self.get_users()
        for user in users:
            user_id = user["id"]
            self.enable_user(user_id=user_id)

    def delete_user(self, user_id):
        """Delete the user.

        :param user_id: User id
        :type user_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def set_user_password(self, user_id, password, temporary=True):
        """Set up a password for the user.

        If temporary is True, the user will have to reset
        the temporary password next time they log in.

        https://www.keycloak.org/docs-api/18.0/rest-api/#_users_resource
        https://www.keycloak.org/docs-api/18.0/rest-api/#_credentialrepresentation

        :param user_id: User id
        :type user_id: str
        :param password: New password
        :type password: str
        :param temporary: True if password is temporary
        :type temporary: bool
        :returns: Response
        :rtype: dict
        """
        payload = {"type": "password", "temporary": temporary, "value": password}
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_RESET_PASSWORD.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def get_credentials(self, user_id):
        """Get user credentials.

        Returns a list of credential belonging to the user.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :returns: Keycloak server response (CredentialRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_CREDENTIALS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_credential(self, user_id, credential_id):
        """Delete credential of the user.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :param: credential_id: credential id
        :type credential_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": user_id,
            "credential_id": credential_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_CREDENTIAL.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def user_logout(self, user_id):
        """Log out the user.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_logout

        :param user_id: User id
        :type user_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_LOGOUT.format(**params_path), data=""
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def user_consents(self, user_id):
        """Get consents granted by the user.

        UserConsentRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_userconsentrepresentation

        :param user_id: User id
        :type user_id: str
        :returns: List of UserConsentRepresentations
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_CONSENTS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_social_logins(self, user_id):
        """Get user social logins.

        Returns a list of federated identities/social logins of which the user has been associated
        with
        :param user_id: User id
        :type user_id: str
        :returns: Federated identities list
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITIES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_user_social_login(self, user_id, provider_id, provider_userid, provider_username):
        """Add a federated identity / social login provider to the user.

        :param user_id: User id
        :type user_id: str
        :param provider_id: Social login provider id
        :type provider_id: str
        :param provider_userid: userid specified by the provider
        :type provider_userid: str
        :param provider_username: username specified by the provider
        :type provider_username: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        payload = {
            "identityProvider": provider_id,
            "userId": provider_userid,
            "userName": provider_username,
        }
        params_path = {"realm-name": self.realm_name, "id": user_id, "provider": provider_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201, 204])

    def delete_user_social_login(self, user_id, provider_id):
        """Delete a federated identity / social login provider from the user.

        :param user_id: User id
        :type user_id: str
        :param provider_id: Social login provider id
        :type provider_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id, "provider": provider_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def send_update_account(
        self, user_id, payload, client_id=None, lifespan=None, redirect_uri=None
    ):
        """Send an update account email to the user.

        An email contains a link the user can click to perform a set of required actions.

        :param user_id: User id
        :type user_id: str
        :param payload: A list of actions for the user to complete
        :type payload: list
        :param client_id: Client id (optional)
        :type client_id: str
        :param lifespan: Number of seconds after which the generated token expires (optional)
        :type lifespan: int
        :param redirect_uri: The redirect uri (optional)
        :type redirect_uri: str

        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
            data=json.dumps(payload),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def send_verify_email(self, user_id, client_id=None, redirect_uri=None):
        """Send a update account email to the user.

        An email contains a link the user can click to perform a set of required actions.

        :param user_id: User id
        :type user_id: str
        :param client_id: Client id (optional)
        :type client_id: str
        :param redirect_uri: Redirect uri (optional)
        :type redirect_uri: str

        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
            data={},
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def get_sessions(self, user_id):
        """Get sessions associated with the user.

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_usersessionrepresentation

        :param user_id: Id of user
        :type user_id: str
        :return: UserSessionRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GET_SESSIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_server_info(self):
        """Get themes, social providers, auth providers, and event listeners available on this server.

        ServerInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_groups(self, query=None):
        """Get groups.

        Returns a list of groups belonging to the realm

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param query: Additional query options
        :type query: dict
        :return: array GroupRepresentation
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.realm_name}
        url = urls_patterns.URL_ADMIN_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def get_group(self, group_id):
        """Get group by id.

        Returns full group details

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param group_id: The group id
        :type group_id: str
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_subgroups(self, group, path):
        """Get subgroups.

        Utility function to iterate through nested group structures

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param group: group (GroupRepresentation)
        :type group: dict
        :param path: group path (string)
        :type path: str
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        for subgroup in group["subGroups"]:
            if subgroup["path"] == path:
                return subgroup
            elif subgroup["subGroups"]:
                for subgroup in group["subGroups"]:
                    result = self.get_subgroups(subgroup, path)
                    if result:
                        return result
        # went through the tree without hits
        return None

    def get_group_members(self, group_id, query=None):
        """Get members by group id.

        Returns group members

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_userrepresentation

        :param group_id: The group id
        :type group_id: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getmembers)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.realm_name, "id": group_id}
        url = urls_patterns.URL_ADMIN_GROUP_MEMBERS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def get_group_by_path(self, path):
        """Get group id based on name or path.

        Returns full group details for a group defined by path

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param path: group path
        :type path: str
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "path": path}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_GROUP_BY_PATH.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_group(self, payload, parent=None, skip_exists=False):
        """Create a group in the Realm.

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param payload: GroupRepresentation
        :type payload: dict
        :param parent: parent group's id. Required to create a sub-group.
        :type parent: str
        :param skip_exists: If true then do not raise an error if it already exists
        :type skip_exists: bool

        :return: Group id for newly created group or None for an existing group
        :rtype: str
        """
        if parent is None:
            params_path = {"realm-name": self.realm_name}
            data_raw = self.connection.raw_post(
                urls_patterns.URL_ADMIN_GROUPS.format(**params_path), data=json.dumps(payload)
            )
        else:
            params_path = {"realm-name": self.realm_name, "id": parent}
            data_raw = self.connection.raw_post(
                urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path), data=json.dumps(payload)
            )

        raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )
        try:
            _last_slash_idx = data_raw.headers["Location"].rindex("/")
            return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203
        except KeyError:
            return

    def update_group(self, group_id, payload):
        """Update group, ignores subgroups.

        GroupRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/#_grouprepresentation

        :param group_id: id of group
        :type group_id: str
        :param payload: GroupRepresentation with updated information.
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_GROUP.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def group_set_permissions(self, group_id, enabled=True):
        """Enable/Disable permissions for a group.

        Cannot delete group if disabled

        :param group_id: id of group
        :type group_id: str
        :param enabled: Enabled flag
        :type enabled: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
            data=json.dumps({"enabled": enabled}),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def group_user_add(self, user_id, group_id):
        """Add user to group (user_id and group_id).

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to add to
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path), data=None
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def group_user_remove(self, user_id, group_id):
        """Remove user from group (user_id and group_id).

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to remove from
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def delete_group(self, group_id):
        """Delete a group in the Realm.

        :param group_id:  id of group to delete
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_clients(self):
        """Get clients.

        Returns a list of clients belonging to the realm

        ClientRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client(self, client_id):
        """Get representation of the client.

        ClientRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_id(self, client_id):
        """Get internal keycloak client id from client-id.

        This is required for further actions against this client.

        :param client_id: clientId in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: client_id (uuid as string)
        :rtype: str
        """
        clients = self.get_clients()

        for client in clients:
            if client_id == client.get("clientId"):
                return client["id"]

        return None

    def get_client_authz_settings(self, client_id):
        """Get authorization json from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_resource(self, client_id, payload, skip_exists=False):
        """Create resources of client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: ResourceRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_resourcerepresentation
        :type payload: dict
        :param skip_exists: Skip the creation in case the resource exists
        :type skip_exists: bool

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def get_client_authz_resources(self, client_id):
        """Get resources from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_role_based_policy(self, client_id, payload, skip_exists=False):
        """Create role-based policy of client.

        Payload example::

            payload={
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "name": "Policy-1",
                "roles": [
                    {
                    "id": id
                    }
                ]
            }

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: No Document
        :type payload: dict
        :param skip_exists: Skip creation in case the object exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes

        """
        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def create_client_authz_resource_based_permission(self, client_id, payload, skip_exists=False):
        """Create resource-based permission of client.

        Payload example::

            payload={
                "type": "resource",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "name": "Permission-Name",
                "resources": [
                    resource_id
                ],
                "policies": [
                    policy_id
                ]

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: PolicyRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_policyrepresentation
        :type payload: dict
        :param skip_exists: Skip creation in case the object already exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes

        """
        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def get_client_authz_scopes(self, client_id):
        """Get scopes from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_scopes(self, client_id, payload):
        """Create scopes for client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :param payload: ScopeRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_ScopeRepresentation
        :type payload: dict
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def get_client_authz_permissions(self, client_id):
        """Get permissions from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_PERMISSIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_policies(self, client_id):
        """Get policies from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_service_account_user(self, client_id):
        """Get service account user from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: UserRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_default_client_scopes(self, client_id):
        """Get all default client scopes from client.

        :param client_id: id of the client in which the new default client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_client_default_client_scope(self, client_id, client_scope_id, payload):
        """Add a client scope to the default client scopes from client.

        Payload example::

            payload={
                "realm":"testrealm",
                "client":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "clientScopeId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            }

        :param client_id: id of the client in which the new default client scope should be added
        :type client_id: str
        :param client_scope_id: id of the new client scope that should be added
        :type client_scope_id: str
        :param payload: dictionary with realm, client and clientScopeId
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_client_default_client_scope(self, client_id, client_scope_id):
        """Delete a client scope from the default client scopes of the client.

        :param client_id: id of the client in which the default client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def get_client_optional_client_scopes(self, client_id):
        """Get all optional client scopes from client.

        :param client_id: id of the client in which the new optional client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_client_optional_client_scope(self, client_id, client_scope_id, payload):
        """Add a client scope to the optional client scopes from client.

        Payload example::

            payload={
                "realm":"testrealm",
                "client":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "clientScopeId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            }

        :param client_id: id of the client in which the new optional client scope should be added
        :type client_id: str
        :param client_scope_id: id of the new client scope that should be added
        :type client_scope_id: str
        :param payload: dictionary with realm, client and clientScopeId
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_client_optional_client_scope(self, client_id, client_scope_id):
        """Delete a client scope from the optional client scopes of the client.

        :param client_id: id of the client in which the optional client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def create_client(self, payload, skip_exists=False):
        """Create a client.

        ClientRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation

        :param skip_exists: If true then do not raise an error if client already exists
        :type skip_exists: bool
        :param payload: ClientRepresentation
        :type payload: dict
        :return: Client ID
        :rtype: str
        """
        if skip_exists:
            client_id = self.get_client_id(client_id=payload["clientId"])

            if client_id is not None:
                return client_id

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def update_client(self, client_id, payload):
        """Update a client.

        :param client_id: Client id
        :type client_id: str
        :param payload: ClientRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_client(self, client_id):
        """Get representation of the client.

        ClientRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_client_installation_provider(self, client_id, provider_id):
        """Get content for given installation provider.

        Related documentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clients_resource

        Possible provider_id list available in the ServerInfoRepresentation#clientInstallations
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_serverinforepresentation

        :param client_id: Client id
        :type client_id: str
        :param provider_id: provider id to specify response format
        :type provider_id: str
        :returns: Installation providers
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "provider-id": provider_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_INSTALLATION_PROVIDER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def get_realm_roles(self, brief_representation=True):
        """Get all roles for the realm or client.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realm_role_members(self, role_name, query=None):
        """Get role members of realm by role name.

        :param role_name: Name of the role.
        :type role_name: str
        :param query: Additional Query parameters
            (see https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_roles_resource)
        :type query: dict
        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        query = query or dict()
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_REALM_ROLES_MEMBERS.format(**params_path), query
        )

    def get_default_realm_role_id(self):
        """Get the ID of the default realm role.

        :return: Realm role ID
        :rtype: str
        """
        all_realm_roles = self.get_realm_roles()
        default_realm_roles = [
            realm_role
            for realm_role in all_realm_roles
            if realm_role["name"] == f"default-roles-{self.realm_name}"
        ]
        return default_realm_roles[0]["id"]

    def get_realm_default_roles(self):
        """Get all the default realm roles.

        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "role-id": self.get_default_realm_role_id()}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES_REALM.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def remove_realm_default_roles(self, payload):
        """Remove a set of default realm roles.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "role-id": self.get_default_realm_role_id()}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def add_realm_default_roles(self, payload):
        """Add a set of default realm roles.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "role-id": self.get_default_realm_role_id()}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_roles(self, client_id, brief_representation=True):
        """Get all roles for the client.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role(self, client_id, role_name):
        """Get client role id by name.

        This is required for further actions with this role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: role_id
        :rtype: str
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "role-name": role_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id, role_name):
        """Get client role id by name.

        This is required for further actions with this role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: role_id
        :rtype: str
        """
        role = self.get_client_role(client_id, role_name)
        return role.get("id")

    def create_client_role(self, client_role_id, payload, skip_exists=False):
        """Create a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param payload: RoleRepresentation
        :type payload: dict
        :param skip_exists: If true then do not raise an error if client role already exists
        :type skip_exists: bool
        :return: Client role name
        :rtype: str
        """
        if skip_exists:
            try:
                res = self.get_client_role(client_id=client_role_id, role_name=payload["name"])
                return res["name"]
            except KeycloakGetError:
                pass

        params_path = {"realm-name": self.realm_name, "id": client_role_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def add_composite_client_roles_to_role(self, client_role_id, role_name, roles):
        """Add composite roles to client role.

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def update_client_role(self, client_role_id, role_name, payload):
        """Update a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :param payload: RoleRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_client_role(self, client_role_id, role_name):
        """Delete a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def assign_client_role(self, user_id, client_id, roles):
        """Assign a client role to a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def get_client_role_members(self, client_id, role_name, **query):
        """Get members by client role.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "role-name": role_name}
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_MEMBERS.format(**params_path), query
        )

    def get_client_role_groups(self, client_id, role_name, **query):
        """Get group members by client role.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "role-name": role_name}
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_GROUPS.format(**params_path), query
        )

    def create_realm_role(self, payload, skip_exists=False):
        """Create a new role for the realm or client.

        :param payload: The role (use RoleRepresentation)
        :type payload: dict
        :param skip_exists: If true then do not raise an error if realm role already exists
        :type skip_exists: bool
        :return: Realm role name
        :rtype: str
        """
        if skip_exists:
            try:
                role = self.get_realm_role(role_name=payload["name"])
                return role["name"]
            except KeycloakGetError:
                pass

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def get_realm_role(self, role_name):
        """Get realm role by role name.

        RoleRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_rolerepresentation

        :param role_name: role's name, not id!
        :type role_name: str
        :return: role
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_realm_role(self, role_name, payload):
        """Update a role for the realm by name.

        :param role_name: The name of the role to be updated
        :type role_name: str
        :param payload: The role (use RoleRepresentation)
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_realm_role(self, role_name):
        """Delete a role for the realm by name.

        :param role_name: The role name
        :type role_name: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def add_composite_realm_roles_to_role(self, role_name, roles):
        """Add composite roles to the role.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def remove_composite_realm_roles_to_role(self, role_name, roles):
        """Remove composite roles from the role.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_composite_realm_roles_of_role(self, role_name):
        """Get composite roles of the role.

        :param role_name: The name of the role
        :type role_name: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles_to_client_scope(self, client_id, roles):
        """Assign realm roles to a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def delete_realm_roles_of_client_scope(self, client_id, roles):
        """Delete realm roles of a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_realm_roles_of_client_scope(self, client_id):
        """Get all realm roles for a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_client_roles_to_client_scope(self, client_id, client_roles_owner_id, roles):
        """Assign client roles to a client's scope.

        :param client_id: id of client (not client-id) who is assigned the roles
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def delete_client_roles_of_client_scope(self, client_id, client_roles_owner_id, roles):
        """Delete client roles of a client's scope.

        :param client_id: id of client (not client-id) who is assigned the roles
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_client_roles_of_client_scope(self, client_id, client_roles_owner_id):
        """Get all client roles for a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles(self, user_id, roles):
        """Assign realm roles to a user.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def delete_realm_roles_of_user(self, user_id, roles):
        """Delete realm roles of a user.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_realm_roles_of_user(self, user_id):
        """Get all realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_available_realm_roles_of_user(self, user_id):
        """Get all available (i.e. unassigned) realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_AVAILABLE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_composite_realm_roles_of_user(self, user_id, brief_representation=True):
        """Get all composite (i.e. implicit) realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_COMPOSITE.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_realm_roles(self, group_id, roles):
        """Assign realm roles to a group.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def delete_group_realm_roles(self, group_id, roles):
        """Delete realm roles of a group.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_group_realm_roles(self, group_id, brief_representation=True):
        """Get all realm roles for a group.

        :param group_id: id of the group
        :type group_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": group_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_client_roles(self, group_id, client_id, roles):
        """Assign client roles to a group.

        :param group_id: id of group
        :type group_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def get_group_client_roles(self, group_id, client_id):
        """Get client roles of a group.

        :param group_id: id of group
        :type group_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_group_client_roles(self, group_id, client_id, roles):
        """Delete client roles of a group.

        :param group_id: id of group
        :type group_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_client_roles_of_user(self, user_id, client_id):
        """Get all client roles for a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return self._get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES, user_id, client_id
        )

    def get_available_client_roles_of_user(self, user_id, client_id):
        """Get available client role-mappings for a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return self._get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, user_id, client_id
        )

    def get_composite_client_roles_of_user(self, user_id, client_id, brief_representation=False):
        """Get composite client role-mappings for a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params = {"briefRepresentation": brief_representation}
        return self._get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, user_id, client_id, **params
        )

    def _get_client_roles_of_user(
        self, client_level_role_mapping_url, user_id, client_id, **params
    ):
        """Get client roles of a single user helper.

        :param client_level_role_mapping_url: Url for the client role mapping
        :type client_level_role_mapping_url: str
        :param user_id: User id
        :type user_id: str
        :param client_id: Client id
        :type client_id: str
        :param params: Additional parameters
        :type params: dict
        :returns: Client roles of a user
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_get(
            client_level_role_mapping_url.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_roles_of_user(self, user_id, client_id, roles):
        """Delete client roles from a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client containing role (not client-id)
        :type client_id: str
        :param roles: roles list or role to delete (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_authentication_flows(self):
        """Get authentication flows.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_FLOWS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authentication_flow_for_id(self, flow_id):
        """Get one authentication flow by it's id.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: the id of a flow NOT it's alias
        :type flow_id: str
        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "flow-id": flow_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_ALIAS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow(self, payload, skip_exists=False):
        """Create a new authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def copy_authentication_flow(self, payload, flow_alias):
        """Copy existing authentication flow under a new name.

        The new name is given as 'newName' attribute of the passed payload.

        :param payload: JSON containing 'newName' attribute
        :type payload: dict
        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_COPY.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def delete_authentication_flow(self, flow_id):
        """Delete authentication flow.

        AuthenticationInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationinforepresentation

        :param flow_id: authentication flow id
        :type flow_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": flow_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_FLOW.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_authentication_flow_executions(self, flow_alias):
        """Get authentication flow executions.

        Returns all execution steps

        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Response(json)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authentication_flow_executions(self, payload, flow_alias):
        """Update an authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[202, 204])

    def get_authentication_flow_execution(self, execution_id):
        """Get authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: the execution ID
        :type execution_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": execution_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow_execution(self, payload, flow_alias):
        """Create an authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_EXECUTION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def delete_authentication_flow_execution(self, execution_id):
        """Delete authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: keycloak client id (not oauth client-id)
        :type execution_id: str
        :return: Keycloak server response (json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": execution_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def create_authentication_flow_subflow(self, payload, flow_alias, skip_exists=False):
        """Create a new sub authentication flow for a given authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_FLOW.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def get_authenticator_providers(self):
        """Get authenticator providers list.

        :return: Authenticator providers
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_PROVIDERS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authenticator_provider_config_description(self, provider_id):
        """Get authenticator's provider configuration description.

        AuthenticatorConfigInfoRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticatorconfiginforepresentation

        :param provider_id: Provider Id
        :type provider_id: str
        :return: AuthenticatorConfigInfoRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "provider-id": provider_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG_DESCRIPTION.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authenticator_config(self, config_id):
        """Get authenticator configuration.

        Returns all configuration details.

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authenticator_config(self, payload, config_id):
        """Update an authenticator configuration.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authenticatorconfigrepresentation

        :param payload: AuthenticatorConfigRepresentation
        :type payload: dict
        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_authenticator_config(self, config_id):
        """Delete a authenticator configuration.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_authentication_management_resource

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": config_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def sync_users(self, storage_id, action):
        """Trigger user sync from provider.

        :param storage_id: The id of the user storage provider
        :type storage_id: str
        :param action: Action can be "triggerFullSync" or "triggerChangedUsersSync"
        :type action: str
        :return: Keycloak server response
        :rtype: bytes
        """
        data = {"action": action}
        params_query = {"action": action}

        params_path = {"realm-name": self.realm_name, "id": storage_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_STORAGE.format(**params_path),
            data=json.dumps(data),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_scopes(self):
        """Get client scopes.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientscopes

        :return: Keycloak server response Array of (ClientScopeRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope(self, client_scope_id):
        """Get client scope.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientscopes

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope_by_name(self, client_scope_name):
        """Get client scope by name.

        Get representation of the client scope identified by the client scope name.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientscopes
        :param client_scope_name: (str) Name of the client scope
        :type client_scope_name: str
        :returns: ClientScopeRepresentation or None
        :rtype: dict
        """
        client_scopes = self.get_client_scopes()
        for client_scope in client_scopes:
            if client_scope["name"] == client_scope_name:
                return client_scope

        return None

    def create_client_scope(self, payload, skip_exists=False):
        """Create a client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientscopes

        :param payload: ClientScopeRepresentation
        :type payload: dict
        :param skip_exists: If true then do not raise an error if client scope already exists
        :type skip_exists: bool
        :return: Client scope id
        :rtype: str
        """
        if skip_exists:
            exists = self.get_client_scope_by_name(client_scope_name=payload["name"])

            if exists is not None:
                return exists["id"]

        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def update_client_scope(self, client_scope_id, payload):
        """Update a client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ClientScopeRepresentation
        :type payload: dict
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_client_scope(self, client_scope_id):
        """Delete existing client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_mappers_from_client_scope(self, client_scope_id):
        """Get a list of all mappers connected to the client scope.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_protocol_mappers_resource
        :param client_scope_id: Client scope id
        :type client_scope_id: str
        :returns: Keycloak server response (ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def add_mapper_to_client_scope(self, client_scope_id, payload):
        """Add a mapper to a client scope.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_create_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def delete_mapper_from_client_scope(self, client_scope_id, protocol_mapper_id):
        """Delete a mapper from a client scope.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_delete_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param protocol_mapper_id: Protocol mapper id
        :type protocol_mapper_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }

        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def update_mapper_in_client_scope(self, client_scope_id, protocol_mapper_id, payload):
        """Update an existing protocol mapper in a client scope.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_protocol_mappers_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param protocol_mapper_id: The id of the protocol mapper which exists in the client scope
               and should to be updated
        :type protocol_mapper_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }

        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def get_default_default_client_scopes(self):
        """Get default default client scopes.

        Return list of default default client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_default_default_client_scope(self, scope_id):
        """Delete default default client scope.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def add_default_default_client_scope(self, scope_id):
        """Add default default client scope.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": scope_id}
        payload = {"realm": self.realm_name, "clientScopeId": scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def get_default_optional_client_scopes(self):
        """Get default optional client scopes.

        Return list of default optional client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_default_optional_client_scope(self, scope_id):
        """Delete default optional client scope.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def add_default_optional_client_scope(self, scope_id):
        """Add default optional client scope.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": scope_id}
        payload = {"realm": self.realm_name, "clientScopeId": scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def get_mappers_from_client(self, client_id):
        """List of all client mappers.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_protocolmapperrepresentation

        :param client_id: Client id
        :type client_id: str
        :returns: KeycloakServerResponse (list of ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path)
        )

        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[200])

    def add_mapper_to_client(self, client_id, payload):
        """Add a mapper to a client.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_create_mapper

        :param client_id: The id of the client
        :type client_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def update_client_mapper(self, client_id, mapper_id, payload):
        """Update client mapper.

        :param client_id: The id of the client
        :type client_id: str
        :param mapper_id: The id of the mapper to be deleted
        :type mapper_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "protocol-mapper-id": mapper_id,
        }

        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def remove_client_mapper(self, client_id, client_mapper_id):
        """Remove a mapper from the client.

        https://www.keycloak.org/docs-api/15.0/rest-api/index.html#_protocol_mappers_resource

        :param client_id: The id of the client
        :type client_id: str
        :param client_mapper_id: The id of the mapper to be deleted
        :type client_mapper_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "protocol-mapper-id": client_mapper_id,
        }

        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def generate_client_secrets(self, client_id):
        """Generate a new secret for the client.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_regeneratesecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path), data=None
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_secrets(self, client_id):
        """Get representation of the client secrets.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientsecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_components(self, query=None):
        """Get components.

        Return a list of components, filtered according to query parameters

        ComponentRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_componentrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: components list
        :rtype: list
        """
        query = query or dict()
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path), data=None, **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_component(self, payload):
        """Create a new component.

        ComponentRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_componentrepresentation

        :param payload: ComponentRepresentation
        :type payload: dict
        :return: Component id
        :rtype: str
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path), data=json.dumps(payload)
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]  # noqa: E203

    def get_component(self, component_id):
        """Get representation of the component.

        :param component_id: Component id

        ComponentRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_componentrepresentation

        :param component_id: Id of the component
        :type component_id: str
        :return: ComponentRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_component(self, component_id, payload):
        """Update the component.

        :param component_id: Component id
        :type component_id: str
        :param payload: ComponentRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_componentrepresentation
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_component(self, component_id):
        """Delete the component.

        :param component_id: Component id
        :type component_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def get_keys(self):
        """Get keys.

        Return a list of keys, filtered according to query parameters

        KeysMetadataRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_key_resource

        :return: keys list
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_KEYS.format(**params_path), data=None
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_events(self, query=None):
        """Get events.

        Return a list of events, filtered according to query parameters

        EventRepresentation array
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_eventrepresentation

        :param query: Additional query parameters
        :type query: dict
        :return: events list
        :rtype: list
        """
        query = query or dict()
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_EVENTS.format(**params_path), data=None, **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def set_events(self, payload):
        """Set realm events configuration.

        RealmEventsConfigRepresentation
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_realmeventsconfigrepresentation

        :param payload: Payload object for the events configuration
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_EVENTS_CONFIG.format(**params_path), data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.raw_get function instead",
    )
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
        return self.connection.raw_get(*args, **kwargs)

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.raw_post function instead",
    )
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
        return self.connection.raw_post(*args, **kwargs)

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.raw_put function instead",
    )
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
        return self.connection.raw_put(*args, **kwargs)

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.raw_delete function instead",
    )
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
        return self.connection.raw_delete(*args, **kwargs)

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.get_token function instead",
    )
    def get_token(self):
        """Get admin token.

        The admin token is then set in the `token` attribute.

        :returns: token
        :rtype: dict
        """
        return self.connection.get_token()

    @deprecation.deprecated(
        deprecated_in="2.13.0",
        removed_in="3.0.0",
        current_version=__version__,
        details="Use the connection.refresh_token function instead",
    )
    def refresh_token(self):
        """Refresh the token.

        :returns: token
        :rtype: dict
        """
        return self.connection.refresh_token()

    def get_client_all_sessions(self, client_id):
        """Get sessions associated with the client.

        UserSessionRepresentation
        http://www.keycloak.org/docs-api/18.0/rest-api/index.html#_usersessionrepresentation

        :param client_id: id of client
        :type client_id: str
        :return: UserSessionRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ALL_SESSIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_sessions_stats(self):
        """Get current session count for all clients with active sessions.

        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_getclientsessionstats

        :return: Dict of clients and session count
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SESSION_STATS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_management_permissions(self, client_id):
        """Get management permissions for a client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_client_management_permissions(self, payload, client_id):
        """Update management permissions for a client.

        ManagementPermissionReference
        https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_managementpermissionreference

        Payload example::

            payload={
                "enabled": true
            }

        :param payload: ManagementPermissionReference
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[200])

    def get_client_authz_policy_scopes(self, client_id, policy_id):
        """Get scopes for a given policy.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "policy-id": policy_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_SCOPES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_policy_resources(self, client_id, policy_id):
        """Get resources for a given policy.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "policy-id": policy_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_RESOURCES.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_scope_permission(self, client_id, scope_id):
        """Get permissions for a given scope.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "scope-id": scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_client_authz_scope_permission(self, payload, client_id, scope_id):
        """Update permissions for a given scope.

        Payload example::

            payload={
                "id": scope_id,
                "name": "My Permission Name",
                "type": "scope",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "resources": [some_resource_id],
                "scopes": [some_scope_id],
                "policies": [some_policy_id],
            }

        :param payload: No Document
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "scope-id": scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[201])

    def get_client_authz_client_policies(self, client_id):
        """Get policies for a given client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def create_client_authz_client_policy(self, payload, client_id):
        """Create a new policy for a given client.

        Payload example::

            payload={
                "type": "client",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "name": "My Policy",
                "clients": [other_client_id],
            }

        :param payload: No Document
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def get_composite_client_roles_of_group(self, client_id, group_id, brief_representation=True):
        """Get the composite client roles of the given group for the given client.

        :param client_id: id of the client.
        :type client_id: str
        :param group_id: id of the group.
        :type group_id: str
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: the composite client roles of the group (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "id": group_id, "client-id": client_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES_COMPOSITE.format(**params_path), **params
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_role_client_level_children(self, client_id, role_id):
        """Get the child roles of which the given composite client role is composed of.

        :param client_id: id of the client.
        :type client_id: str
        :param role_id: id of the role.
        :type role_id: str
        :return: the child roles (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name, "role-id": role_id, "client-id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_CHILDREN.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def upload_certificate(self, client_id, certcont):
        """Upload a new certificate for the client.

        :param client_id: id of the client.
        :type client_id: str
        :param certcont: the content of the certificate.
        :type certcont: str
        :return: dictionary {"certificate": "<certcont>"},
                 where <certcont> is the content of the uploaded certificate.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": client_id, "attr": "jwt.credential"}
        m = MultipartEncoder(fields={"keystoreFormat": "Certificate PEM", "file": certcont})
        new_headers = copy.deepcopy(self.connection.headers)
        new_headers["Content-Type"] = m.content_type
        self.connection.headers = new_headers
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_CERT_UPLOAD.format(**params_path),
            data=m,
            headers=new_headers,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_required_action_by_alias(self, action_alias):
        """Get a required action by its alias.

        :param action_alias: the alias of the required action.
        :type action_alias: str
        :return: the required action (RequiredActionProviderRepresentation).
        :rtype: dict
        """
        actions = self.get_required_actions()
        for a in actions:
            if a["alias"] == action_alias:
                return a
        return None

    def get_required_actions(self):
        """Get the required actions for the realms.

        :return: the required actions (list of RequiredActionProviderRepresentation).
        :rtype: list
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_required_action(self, action_alias, payload):
        """Update a required action.

        :param action_alias: the action alias.
        :type action_alias: str
        :param payload: the new required action (RequiredActionProviderRepresentation).
        :type payload: dict
        :return: empty dictionary.
        :rtype: dict
        """
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        params_path = {"realm-name": self.realm_name, "action-alias": action_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS_ALIAS.format(**params_path), data=payload
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def get_bruteforce_detection_status(self, user_id):
        """Get bruteforce detection status for user.

        :param user_id: User id
        :type user_id: str
        :return: Bruteforce status.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def clear_bruteforce_attempts_for_user(self, user_id):
        """Clear bruteforce attempts for user.

        :param user_id: User id
        :type user_id: str
        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def clear_all_bruteforce_attempts(self):
        """Clear bruteforce attempts for all users in realm.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def clear_keys_cache(self):
        """Clear keys cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_KEYS_CACHE.format(**params_path), data=""
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def clear_realm_cache(self):
        """Clear realm cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_REALM_CACHE.format(**params_path), data=""
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])

    def clear_user_cache(self):
        """Clear user cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.realm_name}
        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_USER_CACHE.format(**params_path), data=""
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[204])
