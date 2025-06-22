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

from __future__ import annotations

import copy
import json

from requests_toolbelt import MultipartEncoder

from . import urls_patterns
from .exceptions import (
    HTTP_ACCEPTED,
    HTTP_BAD_REQUEST,
    HTTP_CONFLICT,
    HTTP_CREATED,
    HTTP_NO_CONTENT,
    HTTP_NOT_FOUND,
    HTTP_OK,
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    raise_error_from_response,
)
from .openid_connection import KeycloakOpenIDConnection


class KeycloakAdmin:
    """
    Keycloak Admin client.

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
    :param verify: Boolean value to enable or disable certificate validation or a string
        containing a path to a CA bundle to use
    :type verify: Union[bool,str]
    :param client_secret_key: client secret key
        (optional, required only for access type confidential)
    :type client_secret_key: str
    :param custom_headers: dict of custom header to pass to each HTML request
    :type custom_headers: dict
    :param user_realm_name: The realm name of the user, if different from realm_name
    :type user_realm_name: str
    :param timeout: connection timeout in seconds
    :type timeout: int
    :param cert: An SSL certificate used by the requested host to authenticate the client.
        Either a path to an SSL certificate file, or two-tuple of
        (certificate file, key file).
    :type cert: Union[str,Tuple[str,str]]
    :param max_retries: The total number of times to retry HTTP requests.
    :type max_retries: int
    :param connection: A KeycloakOpenIDConnection as an alternative to individual params.
    :type connection: KeycloakOpenIDConnection
    """

    PAGE_SIZE = 100

    def __init__(
        self,
        server_url: str | None = None,
        grant_type: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: dict | None = None,
        totp: str | None = None,
        realm_name: str = "master",
        client_id: str = "admin-cli",
        verify: bool | str = True,
        client_secret_key: str | None = None,
        custom_headers: dict | None = None,
        user_realm_name: str | None = None,
        timeout: int = 60,
        cert: str | tuple | None = None,
        max_retries: int = 1,
        connection: KeycloakOpenIDConnection | None = None,
    ) -> None:
        """
        Init method.

        :param server_url: Keycloak server url
        :type server_url: str
        :param grant_type: grant type for authn
        :type grant_type: str
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
        :param verify: Boolean value to enable or disable certificate validation or a string
            containing a path to a CA bundle to use
        :type verify: Union[bool,str]
        :param client_secret_key: client secret key
            (optional, required only for access type confidential)
        :type client_secret_key: str
        :param custom_headers: dict of custom header to pass to each HTML request
        :type custom_headers: dict
        :param user_realm_name: The realm name of the user, if different from realm_name
        :type user_realm_name: str
        :param timeout: connection timeout in seconds
        :type timeout: int
        :param cert: An SSL certificate used by the requested host to authenticate the client.
            Either a path to an SSL certificate file, or two-tuple of (certificate file, key file).
        :type cert: Union[str,Tuple[str,str]]
        :param max_retries: The total number of times to retry HTTP requests.
        :type max_retries: int
        :param connection: An OpenID Connection as an alternative to individual params.
        :type connection: KeycloakOpenIDConnection
        """
        self.connection = connection or KeycloakOpenIDConnection(
            server_url=server_url,
            grant_type=grant_type,
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
            cert=cert,
            max_retries=max_retries,
        )

    @property
    def connection(self) -> KeycloakOpenIDConnection:
        """
        Get connection.

        :returns: Connection manager
        :rtype: KeycloakOpenIDConnection
        """
        return self._connection

    @connection.setter
    def connection(self, value: KeycloakOpenIDConnection) -> None:
        self._connection = value

    def __fetch_all(self, url: str, query: dict | None = None) -> list:
        """
        Paginate over get requests.

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
                self.connection.raw_get(url, **query),
                KeycloakGetError,
            )
            if not partial_results:
                break
            results.extend(partial_results)
            if len(partial_results) < query["max"]:
                break
            page += 1

        return results

    def __fetch_paginated(self, url: str, query: dict | None = None) -> dict | list:
        """
        Make a specific paginated request.

        :param url: The url on which the query is executed
        :type url: str
        :param query: Pagination settings
        :type query: dict
        :returns: Response
        :rtype: dict
        """
        query = query or {}
        return raise_error_from_response(self.connection.raw_get(url, **query), KeycloakGetError)

    def get_current_realm(self) -> str:
        """
        Return the currently configured realm.

        :returns: Currently configured realm name
        :rtype: str
        """
        return self.connection.realm_name

    def change_current_realm(self, realm_name: str) -> None:
        """
        Change the current realm.

        :param realm_name: The name of the realm to be configured as current
        :type realm_name: str
        """
        self.connection.realm_name = realm_name

    def import_realm(self, payload: dict) -> dict | bytes:
        """
        Import a new realm from a RealmRepresentation.

        Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :return: RealmRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALMS,
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def partial_import_realm(self, realm_name: str, payload: dict) -> dict | bytes:
        """
        Partial import realm configuration from PartialImportRepresentation.

        Realm partialImport is used for modifying configuration of existing realm.

        PartialImportRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_partialimportrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: PartialImportRepresentation
        :type payload: dict

        :return: PartialImportResponse
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_PARTIAL_IMPORT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    def export_realm(
        self,
        export_clients: bool = False,
        export_groups_and_role: bool = False,
    ) -> dict:
        """
        Export the realm configurations in the json format.

        RealmRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_partialexport

        :param export_clients: Skip if not want to export realm clients
        :type export_clients: bool
        :param export_groups_and_role: Skip if not want to export realm groups and roles
        :type export_groups_and_role: bool

        :return: realm configurations JSON
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "export-clients": export_clients,
            "export-groups-and-roles": export_groups_and_role,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_EXPORT.format(**params_path),
            data="",
            exportClients=export_clients,
            exportGroupsAndRoles=export_groups_and_role,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_realms(self) -> list:
        """
        List all realms in Keycloak deployment.

        :return: realms list
        :rtype: list
        """
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_REALMS)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realm(self, realm_name: str) -> dict:
        """
        Get a specific realm.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: RealmRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def create_realm(self, payload: dict, skip_exists: bool = False) -> dict | bytes:
        """
        Create a realm.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :param skip_exists: Skip if Realm already exist.
        :type skip_exists: bool
        :return: Keycloak server response (RealmRepresentation)
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALMS,
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED]
            + ([HTTP_BAD_REQUEST, HTTP_CONFLICT] if skip_exists else []),
        )

    def update_realm(self, realm_name: str, payload: dict) -> dict | bytes:
        """
        Update a realm.

        This will only update top level attributes and will ignore any user,
        role, or client information in the payload.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: RealmRepresentation
        :type payload: dict
        :return: Http response
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_realm(self, realm_name: str) -> dict | bytes:
        """
        Delete a realm.

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: Http response
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_organizations(self, query: dict | None = None) -> list:
        """
        Fetch all organizations.

        Returns a list of organizations, filtered according to query parameters

        OrganizationRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :return: List of organizations
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_ORGANIZATIONS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    async def a_get_organizations(self, query: dict | None = None) -> list:
        """
        Fetch all organizations asynchronously.

        Returns a list of organizations, filtered according to query parameters

        OrganizationRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :return: List of organizations
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_ORGANIZATIONS.format(**params_path)

        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    def get_organization(self, organization_id: str) -> dict:
        """
        Get representation of the organization.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str

        :return: Organization details
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path)
        )

        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_organization(self, organization_id: str) -> dict:
        """
        Get representation of the organization asynchronously.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str

        :return: Organization details
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path)
        )

        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_organization(self, payload: dict) -> str | None:
        """
        Create a new organization.

        Organization name and alias must be unique.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param payload: Dictionary containing organization details
        :type payload: dict
        :return: org_id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATIONS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        try:
            _last_slash_idx = data_raw.headers["Location"].rindex("/")
            return data_raw.headers["Location"][_last_slash_idx + 1 :]
        except KeyError:
            return None

    async def a_create_organization(self, payload: dict) -> str | None:
        """
        Create a new organization asynchronously.

        Organization name and alias must be unique.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param payload: Dictionary containing organization details
        :type payload: dict
        :return: org_id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}

        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATIONS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        try:
            _last_slash_idx = data_raw.headers["Location"].rindex("/")
            return data_raw.headers["Location"][_last_slash_idx + 1 :]
        except KeyError:
            return None

    def update_organization(self, organization_id: str, payload: dict) -> dict | bytes:
        """
        Update an existing organization.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :param payload: Dictionary with updated organization details
        :type payload: dict
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPutError, expected_codes=[HTTP_NO_CONTENT]
        )

    async def a_update_organization(self, organization_id: str, payload: dict) -> dict | bytes:
        """
        Update an existing organization asynchronously.

        OrganizationRepresentation:
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :param payload: Dictionary with updated organization details
        :type payload: dict
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw, KeycloakPutError, expected_codes=[HTTP_NO_CONTENT]
        )

    def delete_organization(self, organization_id: str) -> dict | bytes:
        """
        Delete an organization.

        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path)
        )

        return raise_error_from_response(
            data_raw, KeycloakDeleteError, expected_codes=[HTTP_NO_CONTENT]
        )

    async def a_delete_organization(self, organization_id: str) -> dict | bytes:
        """
        Delete an organization asynchronously.

        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_ORGANIZATION_BY_ID.format(**params_path)
        )

        return raise_error_from_response(
            data_raw, KeycloakDeleteError, expected_codes=[HTTP_NO_CONTENT]
        )

    def get_organization_idps(self, organization_id: str) -> list:
        """
        Get IDPs by organization id.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#IdentityProviderRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :return: List of IDPs in the organization
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDPS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_organization_idps(self, organization_id: str) -> list:
        """
        Get IDPs by organization id asynchronously.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#IdentityProviderRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :return: List of IDPs in the organization
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDPS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def organization_idp_add(self, organization_id: str, idp_alias: str) -> dict | bytes:
        """
        Add an IDP to an organization.

        :param organization_id: ID of the organization
        :type organization_id: str
        :param idp_alias: Alias of the IDP
        :type idp_alias: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDPS.format(**params_path), data=idp_alias
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[HTTP_NO_CONTENT]
        )

    async def a_organization_idp_add(self, organization_id: str, idp_alias: str) -> dict | bytes:
        """
        Add an IDP to an organization asynchronously.

        :param organization_id: ID of the organization
        :type organization_id: str
        :param idp_alias: Alias of the IDP
        :type idp_alias: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDPS.format(**params_path), data=idp_alias
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[HTTP_NO_CONTENT]
        )

    def organization_idp_remove(self, organization_id: str, idp_alias: str) -> dict | bytes:
        """
        Remove an IDP from an organization.

        :param organization_id: ID of the organization
        :type organization_id: str
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
            "idp_alias": idp_alias,
        }

        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDP_BY_ALIAS.format(**params_path)
        )

        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_organization_idp_remove(
        self, organization_id: str, idp_alias: str
    ) -> dict | bytes:
        """
        Remove an IDP from an organization asynchronously.

        :param organization_id: ID of the organization
        :type organization_id: str
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
            "idp_alias": idp_alias,
        }

        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_ORGANIZATION_IDP_BY_ALIAS.format(**params_path)
        )

        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_user_organizations(self, user_id: str) -> list:
        """
        Get organizations by user id.

        OrganizationRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param user_id: ID of the user
        :type user_id: str
        :return: List of organizations the user is member of
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "user_id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_ORGANIZATIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_user_organizations(self, user_id: str) -> list:
        """
        Get organizations by user id asynchronously.

        OrganizationRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#OrganizationRepresentation

        :param user_id: ID of the user
        :type user_id: str
        :return: List of organizations the user is member of
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "user_id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_ORGANIZATIONS.format(**params_path)
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_organization_members(self, organization_id: str, query: dict | None = None) -> list:
        """
        Get members by organization id.

        Returns organization members, filtered according to query parameters

        MemberRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#MemberRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#_organizations)
        :type query: dict
        :return: List of users in the organization
        :rtype: list
        """
        query = query or {}
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        url = urls_patterns.URL_ADMIN_ORGANIZATION_MEMBERS.format(**params_path)
        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    async def a_get_organization_members(
        self, organization_id: str, query: dict | None = None
    ) -> list:
        """
        Get members by organization id asynchronously.

        Returns organization members, filtered according to query parameters

        MemberRepresentation
        https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#MemberRepresentation

        :param organization_id: ID of the organization
        :type organization_id: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/26.1.4/rest-api/index.html#_organizations)
        :type query: dict
        :return: List of users in the organization
        :rtype: list
        """
        query = query or {}
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        url = urls_patterns.URL_ADMIN_ORGANIZATION_MEMBERS.format(**params_path)
        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    def organization_user_add(self, user_id: str, organization_id: str) -> dict | bytes:
        """
        Add a user to an organization.

        :param user_id: ID of the user to be added
        :type user_id: str
        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATION_MEMBERS.format(**params_path), data=user_id
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED]
        )

    async def a_organization_user_add(self, user_id: str, organization_id: str) -> dict | bytes:
        """
        Add a user to an organization asynchronously.

        :param user_id: ID of the user to be added
        :type user_id: str
        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
        }

        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_ORGANIZATION_MEMBERS.format(**params_path), data=user_id
        )
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED]
        )

    def organization_user_remove(self, user_id: str, organization_id: str) -> dict | bytes:
        """
        Remove a user from an organization.

        :param user_id: ID of the user to be removed
        :type user_id: str
        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
            "user_id": user_id,
        }

        url = urls_patterns.URL_ADMIN_ORGANIZATION_DEL_MEMBER_BY_ID.format(**params_path)
        data_raw = self.connection.raw_delete(url)
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_organization_user_remove(self, user_id: str, organization_id: str) -> dict | bytes:
        """
        Remove a user from an organization asynchronously.

        :param user_id: ID of the user to be removed
        :type user_id: str
        :param organization_id: ID of the organization
        :type organization_id: str
        :return: Response from Keycloak
        :rtype: dict | bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "organization_id": organization_id,
            "user_id": user_id,
        }

        url = urls_patterns.URL_ADMIN_ORGANIZATION_DEL_MEMBER_BY_ID.format(**params_path)
        data_raw = await self.connection.a_raw_delete(url)
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_users(self, query: dict | None = None) -> list:
        """
        Get all users.

        Return a list of users, filtered according to query parameters

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: users list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_USERS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def create_idp(self, payload: dict) -> dict | bytes:
        """
        Create an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :param: payload: IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_IDPS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def update_idp(self, idp_alias: str, payload: dict) -> dict | bytes:
        """
        Update an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identity_providers_resource

        :param: idp_alias: alias for IdP to update
        :type idp_alias: str
        :param: payload: The IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_IDP.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def add_mapper_to_idp(self, idp_alias: str, payload: dict) -> dict | bytes:
        """
        Create an ID Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityprovidermapperrepresentation

        :param: idp_alias: alias for Idp to add mapper in
        :type idp_alias: str
        :param: payload: IdentityProviderMapperRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "idp-alias": idp_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def update_mapper_in_idp(self, idp_alias: str, mapper_id: str, payload: dict) -> dict | bytes:
        """
        Update an IdP mapper.

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_update

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
            "realm-name": self.connection.realm_name,
            "idp-alias": idp_alias,
            "mapper-id": mapper_id,
        }

        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_IDP_MAPPER_UPDATE.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_idp_mappers(self, idp_alias: str) -> list:
        """
        Get IDP mappers.

        Returns a list of ID Providers mappers

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getmappers

        :param: idp_alias: alias for Idp to fetch mappers
        :type idp_alias: str
        :return: array IdentityProviderMapperRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "idp-alias": idp_alias}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_idps(self) -> list:
        """
        Get IDPs.

        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_IDPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_idp(self, idp_alias: str) -> dict:
        """
        Get IDP provider.

        Get the representation of a specific IDP Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :param: idp_alias: alias for IdP to get
        :type idp_alias: str
        :return: IdentityProviderRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_IDP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_idp(self, idp_alias: str) -> dict | bytes:
        """
        Delete an ID Provider.

        :param: idp_alias: idp alias name
        :type idp_alias: str
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_IDP.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def create_user(self, payload: dict, exist_ok: bool = False) -> str:
        """
        Create a new user.

        Username must be unique

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation
        :type payload: dict
        :param exist_ok: If False, raise KeycloakGetError if username already exists.
            Otherwise, return existing user ID.
        :type exist_ok: bool

        :return: user_id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}

        if exist_ok:
            exists = self.get_user_id(username=payload["username"])

            if exists is not None:
                return str(exists)

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USERS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def users_count(self, query: dict | None = None) -> int:
        """
        Count users.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_users_resource

        :param query: (dict) Query parameters for users count
        :type query: dict

        :return: counter
        :rtype: int
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USERS_COUNT.format(**params_path),
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_id(self, username: str) -> str | None:
        """
        Get internal keycloak user id from username.

        This is required for further actions against this user.

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation
        :type username: str

        :return: user_id
        :rtype: str
        """
        lower_user_name = username.lower()
        users = self.get_users(query={"username": lower_user_name, "max": 1, "exact": True})
        return users[0]["id"] if len(users) == 1 else None

    def get_user(self, user_id: str, user_profile_metadata: bool = False) -> dict:
        """
        Get representation of the user.

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param user_id: User id
        :type user_id: str
        :param user_profile_metadata: Whether to include user profile metadata in the response
        :type user_profile_metadata: bool
        :return: UserRepresentation
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER.format(**params_path),
            userProfileMetadata=user_profile_metadata,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_groups(
        self,
        user_id: str,
        query: dict | None = None,
        brief_representation: bool = True,
    ) -> list:
        """
        Get user groups.

        Returns a list of groups of which the user is a member

        :param user_id: User id
        :type user_id: str
        :param query: Additional query options
        :type query: dict
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: user groups list
        :rtype: list
        """
        query = query or {}

        params = {"briefRepresentation": brief_representation}

        query.update(params)

        params_path = {"realm-name": self.connection.realm_name, "id": user_id}

        url = urls_patterns.URL_ADMIN_USER_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def update_user(self, user_id: str, payload: dict) -> dict | bytes:
        """
        Update the user.

        :param user_id: User id
        :type user_id: str
        :param payload: UserRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_USER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def disable_user(self, user_id: str) -> dict | bytes:
        """
        Disable the user from the realm. Disabled users can not log in.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return self.update_user(user_id=user_id, payload={"enabled": False})

    def enable_user(self, user_id: str) -> dict | bytes:
        """
        Enable the user from the realm.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return self.update_user(user_id=user_id, payload={"enabled": True})

    def disable_all_users(self) -> None:
        """Disable all existing users."""
        users = self.get_users()
        for user in users:
            user_id = user["id"]
            self.disable_user(user_id=user_id)

    def enable_all_users(self) -> None:
        """Disable all existing users."""
        users = self.get_users()
        for user in users:
            user_id = user["id"]
            self.enable_user(user_id=user_id)

    def delete_user(self, user_id: str) -> dict | bytes:
        """
        Delete the user.

        :param user_id: User id
        :type user_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def set_user_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = True,
    ) -> dict | bytes:
        """
        Set up a password for the user.

        If temporary is True, the user will have to reset
        the temporary password next time they log in.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_users_resource
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_credentialrepresentation

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
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_RESET_PASSWORD.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_credentials(self, user_id: str) -> list:
        """
        Get user credentials.

        Returns a list of credential belonging to the user.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :returns: Keycloak server response (CredentialRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_CREDENTIALS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_credential(self, user_id: str, credential_id: str) -> dict | bytes:
        """
        Delete credential of the user.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :param: credential_id: credential id
        :type credential_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "credential_id": credential_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_CREDENTIAL.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def user_logout(self, user_id: str) -> dict | bytes:
        """
        Log out the user.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_logout

        :param user_id: User id
        :type user_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_LOGOUT.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def user_consents(self, user_id: str) -> list:
        """
        Get consents granted by the user.

        UserConsentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userconsentrepresentation

        :param user_id: User id
        :type user_id: str
        :returns: List of UserConsentRepresentations
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_CONSENTS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def revoke_consent(self, user_id: str, client_id: str) -> dict | bytes:
        """
        Revoke consent and offline tokens for particular client from user.

        :param user_id: User id
        :type user_id: str
        :param client_id: Client id
        :type client_id: str

        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_CONSENT.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_user_social_logins(self, user_id: str) -> list:
        """
        Get user social logins.

        Returns a list of federated identities/social logins of which the user has been associated
        with
        :param user_id: User id
        :type user_id: str
        :returns: Federated identities list
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITIES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_user_social_login(
        self,
        user_id: str,
        provider_id: str,
        provider_userid: str,
        provider_username: str,
    ) -> dict | bytes:
        """
        Add a federated identity / social login provider to the user.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "provider": provider_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED, HTTP_NO_CONTENT],
        )

    def delete_user_social_login(self, user_id: str, provider_id: str) -> dict | bytes:
        """
        Delete a federated identity / social login provider from the user.

        :param user_id: User id
        :type user_id: str
        :param provider_id: Social login provider id
        :type provider_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "provider": provider_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def send_update_account(
        self,
        user_id: str,
        payload: dict,
        client_id: str | None = None,
        lifespan: int | None = None,
        redirect_uri: str | None = None,
    ) -> dict | bytes:
        """
        Send an update account email to the user.

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
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
            data=json.dumps(payload),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def send_verify_email(
        self,
        user_id: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict | bytes:
        """
        Send a update account email to the user.

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
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redirect_uri": redirect_uri}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
            data={},
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def get_sessions(self, user_id: str) -> list:
        """
        Get sessions associated with the user.

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_usersessionrepresentation

        :param user_id: Id of user
        :type user_id: str
        :return: UserSessionRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GET_SESSIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_server_info(self) -> dict:
        """
        Get themes, social providers, etc. on this server.

        ServerInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_groups(self, query: dict | None = None, full_hierarchy: bool = False) -> list:
        """
        Get groups.

        Returns a list of groups belonging to the realm

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        Notice that when using full_hierarchy=True, the response will be a nested structure
        containing all the children groups. If used with query parameters, the full_hierarchy
        will be applied to the received groups only.

        :param query: Additional query options
        :type query: dict
        :param full_hierarchy: If True, return all of the nested children groups, otherwise only
            the first level children are returned
        :type full_hierarchy: bool
        :return: array GroupRepresentation
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            groups = self.__fetch_paginated(url, query)
        else:
            groups = self.__fetch_all(url, query)

        # For version +23.0.0
        for group in groups:
            if group.get("subGroupCount"):
                group["subGroups"] = self.get_group_children(
                    group_id=group.get("id"),
                    full_hierarchy=full_hierarchy,
                )

        return groups

    def get_group(self, group_id: str, full_hierarchy: bool = False) -> dict:
        """
        Get group by id.

        Returns full group details

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param group_id: The group id
        :type group_id: str
        :param full_hierarchy: If True, return all of the nested children groups, otherwise only
            the first level children are returned
        :type full_hierarchy: bool
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        response = self.connection.raw_get(urls_patterns.URL_ADMIN_GROUP.format(**params_path))

        if response.status_code >= HTTP_BAD_REQUEST:
            return raise_error_from_response(response, KeycloakGetError)

        # For version +23.0.0
        group = response.json()
        if group.get("subGroupCount"):
            group["subGroups"] = self.get_group_children(
                group.get("id"),
                full_hierarchy=full_hierarchy,
            )

        return group

    def get_subgroups(self, group: str, path: str) -> dict | None:
        """
        Get subgroups.

        Utility function to iterate through nested group structures

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

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
            if subgroup["subGroups"]:
                for _subgroup in group["subGroups"]:
                    result = self.get_subgroups(_subgroup, path)
                    if result:
                        return result

        # went through the tree without hits
        return None

    def get_group_children(
        self,
        group_id: str,
        query: dict | None = None,
        full_hierarchy: bool = False,
    ) -> dict:
        """
        Get group children by parent id.

        Returns full group children details

        :param group_id: The parent group id
        :type group_id: str
        :param query: Additional query options
        :type query: dict
        :param full_hierarchy: If True, return all of the nested children groups
        :type full_hierarchy: bool
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        :raises ValueError: If both query and full_hierarchy parameters are used
        """
        query = query or {}
        if query and full_hierarchy:
            msg = "Cannot use both query and full_hierarchy parameters"
            raise ValueError(msg)

        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        url = urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path)
        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)
        res = self.__fetch_all(url, query)

        if not full_hierarchy:
            return res

        for group in res:
            if group.get("subGroupCount"):
                group["subGroups"] = self.get_group_children(
                    group_id=group.get("id"),
                    full_hierarchy=full_hierarchy,
                )

        return res

    def get_group_members(self, group_id: str, query: dict | None = None) -> list:
        """
        Get members by group id.

        Returns group members

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_userrepresentation

        :param group_id: The group id
        :type group_id: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getmembers)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        url = urls_patterns.URL_ADMIN_GROUP_MEMBERS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def get_group_by_path(self, path: str) -> dict:
        """
        Get group id based on name or path.

        Returns full group details for a group defined by path

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param path: group path
        :type path: str
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "path": path}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUP_BY_PATH.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, [HTTP_OK, HTTP_NOT_FOUND])

    def create_group(
        self,
        payload: dict,
        parent: str | None = None,
        skip_exists: bool = False,
    ) -> str | None:
        """
        Create a group in the Realm.

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

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
            params_path = {"realm-name": self.connection.realm_name}
            data_raw = self.connection.raw_post(
                urls_patterns.URL_ADMIN_GROUPS.format(**params_path),
                data=json.dumps(payload),
            )
        else:
            params_path = {"realm-name": self.connection.realm_name, "id": parent}
            data_raw = self.connection.raw_post(
                urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path),
                data=json.dumps(payload),
            )

        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        try:
            _last_slash_idx = data_raw.headers["Location"].rindex("/")
            return data_raw.headers["Location"][_last_slash_idx + 1 :]
        except KeyError:
            return None

    def update_group(self, group_id: str, payload: dict) -> dict | bytes:
        """
        Update group, ignores subgroups.

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param group_id: id of group
        :type group_id: str
        :param payload: GroupRepresentation with updated information.
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_GROUP.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def groups_count(self, query: dict | None = None) -> dict:
        """
        Count groups.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_groups

        :param query: (dict) Query parameters for groups count
        :type query: dict

        :return: Keycloak Server Response
        :rtype: dict
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_COUNT.format(**params_path),
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def group_set_permissions(self, group_id: str, enabled: bool = True) -> bytes:
        """
        Enable/Disable permissions for a group.

        Cannot delete group if disabled

        :param group_id: id of group
        :type group_id: str
        :param enabled: Enabled flag
        :type enabled: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
            data=json.dumps({"enabled": enabled}),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def group_user_add(self, user_id: str, group_id: str) -> bytes:
        """
        Add user to group (user_id and group_id).

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to add to
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "group-id": group_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path),
            data=None,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def group_user_remove(self, user_id: str, group_id: str) -> bytes:
        """
        Remove user from group (user_id and group_id).

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to remove from
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "group-id": group_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_group(self, group_id: str) -> dict | bytes:
        """
        Delete a group in the Realm.

        :param group_id:  id of group to delete
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_clients(self) -> list:
        """
        Get clients.

        Returns a list of clients belonging to the realm

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client(self, client_id: str) -> dict:
        """
        Get representation of the client.

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_id(self, client_id: str) -> str | None:
        """
        Get internal keycloak client id from client-id.

        This is required for further actions against this client.

        :param client_id: clientId in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: client_id (uuid as string)
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
            clientId=client_id,
        )
        data_response = raise_error_from_response(data_raw, KeycloakGetError)

        for client in data_response:
            if client_id == client.get("clientId"):
                return client["id"]

        return None

    def get_client_authz_settings(self, client_id: str) -> dict:
        """
        Get authorization json from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_resource(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> dict | bytes:
        """
        Create resources of client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type payload: dict
        :param skip_exists: Skip the creation in case the resource exists
        :type skip_exists: bool

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def update_client_authz_resource(
        self,
        client_id: str,
        resource_id: str,
        payload: dict,
    ) -> dict | bytes:
        """
        Update resource of client.

        Any parameter missing from the ResourceRepresentation in the payload WILL be set
        to default by the Keycloak server.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_client_authz_resource(self, client_id: str, resource_id: str) -> bytes:
        """
        Delete a client resource.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_authz_resources(self, client_id: str) -> list:
        """
        Get resources from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (ResourceRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_resource(self, client_id: str, resource_id: str) -> dict | bytes:
        """
        Get a client resource.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response (ResourceRepresentation)
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def create_client_authz_role_based_policy(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> dict | bytes:
        """
        Create role-based policy of client.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: No Document
        :type payload: dict
        :param skip_exists: Skip creation in case the object exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes

        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def create_client_authz_policy(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> dict | bytes:
        """
        Create an authz policy of client.

        Payload example::

            payload={
                "name": "Policy-time-based",
                "type": "time",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {
                    "hourEnd": "18",
                    "hour": "9"
                }
            }

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: No Document
        :type payload: dict
        :param skip_exists: Skip creation in case the object exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes

        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
            permission=False,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def create_client_authz_resource_based_permission(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create resource-based permission of client.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type payload: dict
        :param skip_exists: Skip creation in case the object already exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes

        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}

        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def get_client_authz_scopes(self, client_id: str) -> list:
        """
        Get scopes from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_scopes(self, client_id: str, payload: dict) -> bytes:
        """
        Create scopes for client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :param payload: ScopeRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_ScopeRepresentation
        :type payload: dict
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def get_client_authz_permissions(self, client_id: str) -> list:
        """
        Get permissions from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_PERMISSIONS.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_policies(self, client_id: str) -> list:
        """
        Get policies from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path),
            max=-1,
            permission=False,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_authz_policy(self, client_id: str, policy_id: str) -> dict | bytes:
        """
        Delete a policy from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_authz_policy(self, client_id: str, policy_id: str) -> dict:
        """
        Get a policy from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_service_account_user(self, client_id: str) -> dict:
        """
        Get service account user from client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: UserRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_default_client_scopes(self, client_id: str) -> list:
        """
        Get all default client scopes from client.

        :param client_id: id of the client in which the new default client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_client_default_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
        payload: dict,
    ) -> bytes:
        """
        Add a client scope to the default client scopes from client.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_client_default_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
    ) -> dict | bytes:
        """
        Delete a client scope from the default client scopes of the client.

        :param client_id: id of the client in which the default client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def get_client_optional_client_scopes(self, client_id: str) -> list:
        """
        Get all optional client scopes from client.

        :param client_id: id of the client in which the new optional client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_client_optional_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
        payload: dict,
    ) -> bytes:
        """
        Add a client scope to the optional client scopes from client.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_client_optional_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
    ) -> dict | bytes:
        """
        Delete a client scope from the optional client scopes of the client.

        :param client_id: id of the client in which the optional client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def create_initial_access_token(self, count: int = 1, expiration: int = 1) -> dict | bytes:
        """
        Create an initial access token.

        :param count: Number of clients that can be registered
        :type count: int
        :param expiration: Days until expireation
        :type expiration: int
        :return: initial access token
        :rtype: dict
        """
        payload = {"count": count, "expiration": expiration}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_INITIAL_ACCESS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    def create_client(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a client.

        ClientRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

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

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def update_client(self, client_id: str, payload: dict) -> bytes:
        """
        Update a client.

        :param client_id: Client id
        :type client_id: str
        :param payload: ClientRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_client(self, client_id: str) -> bytes:
        """
        Get representation of the client.

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_installation_provider(self, client_id: str, provider_id: str) -> list:
        """
        Get content for given installation provider.

        Related documentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource

        Possible provider_id list available in the ServerInfoRepresentation#clientInstallations
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_serverinforepresentation

        :param client_id: Client id
        :type client_id: str
        :param provider_id: provider id to specify response format
        :type provider_id: str
        :returns: Installation providers
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "provider-id": provider_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_INSTALLATION_PROVIDER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def get_realm_users_profile(self) -> dict:
        """
        Get list of attributes and group for given realm.

        Related documentation:
        https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#_get_adminrealmsrealmusersprofile

        Return https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#UPConfig
        :returns: UPConfig

        """
        params_path = {"realm-name": self.connection.realm_name}

        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_USER_PROFILE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def get_realm_roles(
        self, brief_representation: bool = True, search_text: str = "", query: dict | None = None
    ) -> list:
        """
        Get all roles for the realm or client.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :param search_text: optional search text to limit the returned result.
        :type search_text: str
        :param query: Query parameters (optional)
        :type query: dict
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        params = {"briefRepresentation": brief_representation}
        url = urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path)

        if search_text is not None and search_text.strip() != "":
            params["search"] = search_text

        if "first" in query and "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, params)

    def get_realm_role_groups(
        self,
        role_name: str,
        query: dict | None = None,
        brief_representation: bool = True,
    ) -> list:
        """
        Get role groups of realm by role name.

        :param role_name: Name of the role.
        :type role_name: str
        :param query: Additional Query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_parameters_226)
        :type query: dict
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak Server Response (GroupRepresentation)
        :rtype: list
        """
        query = query or {}

        params = {"briefRepresentation": brief_representation}

        query.update(params)

        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}

        url = urls_patterns.URL_ADMIN_REALM_ROLES_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def get_realm_role_members(self, role_name: str, query: dict | None = None) -> list:
        """
        Get role members of realm by role name.

        :param role_name: Name of the role.
        :type role_name: str
        :param query: Additional Query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_roles_resource)
        :type query: dict
        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_REALM_ROLES_MEMBERS.format(**params_path),
            query,
        )

    def get_default_realm_role_id(self) -> str:
        """
        Get the ID of the default realm role.

        :return: Realm role ID
        :rtype: str
        """
        all_realm_roles = self.get_realm_roles()
        default_realm_roles = [
            realm_role
            for realm_role in all_realm_roles
            if realm_role["name"] == f"default-roles-{self.connection.realm_name}".lower()
        ]
        return default_realm_roles[0]["id"]

    def get_realm_default_roles(self) -> list:
        """
        Get all the default realm roles.

        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": self.get_default_realm_role_id(),
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES_REALM.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def remove_realm_default_roles(self, payload: dict) -> dict | bytes:
        """
        Remove a set of default realm roles.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": self.get_default_realm_role_id(),
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def add_realm_default_roles(self, payload: dict) -> dict | bytes:
        """
        Add a set of default realm roles.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": self.get_default_realm_role_id(),
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_roles(self, client_id: str, brief_representation: bool = True) -> list:
        """
        Get all roles for the client.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role(self, client_id: str, role_name: str) -> dict:
        """
        Get client role by name.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: Role object
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id: str, role_name: str) -> str | None:
        """
        Get client role id by name.

        This is required for further actions with this role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: role_id
        :rtype: str
        """
        role = self.get_client_role(client_id, role_name)
        return role.get("id")

    def create_client_role(
        self,
        client_role_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> str:
        """
        Create a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

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

        params_path = {"realm-name": self.connection.realm_name, "id": client_role_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def add_composite_client_roles_to_role(
        self,
        client_role_id: str,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Add composite roles to client role.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def remove_composite_client_roles_from_role(
        self,
        client_role_id: str,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Remove composite roles from a client role.

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def update_client_role(self, client_id: str, role_name: str, payload: dict) -> bytes:
        """
        Update a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :param payload: RoleRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_client_role(self, client_role_id: str, role_name: str) -> bytes:
        """
        Delete a client role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def assign_client_role(self, user_id: str, client_id: str, roles: str | list) -> bytes:
        """
        Assign a client role to a user.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_role_members(self, client_id: str, role_name: str, **query: dict) -> list:
        """
        Get members by client role.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_MEMBERS.format(**params_path),
            query,
        )

    def get_client_role_groups(self, client_id: str, role_name: str, **query: dict) -> list:
        """
        Get group members by client role.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        return self.__fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_GROUPS.format(**params_path),
            query,
        )

    def get_role_by_id(self, role_id: str) -> dict:
        """
        Get a specific role's representation.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: id of role
        :type role_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def update_role_by_id(self, role_id: str, payload: dict) -> bytes:
        """
        Update the role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param payload: RoleRepresentation
        :type payload: dict
        :param role_id: id of role
        :type role_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_role_by_id(self, role_id: str) -> bytes:
        """
        Delete a role by its id.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: id of role
        :type role_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def create_realm_role(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a new role for the realm or client.

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

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def get_realm_role(self, role_name: str) -> dict:
        """
        Get realm role by role name.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_name: role's name, not id!
        :type role_name: str
        :return: role
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_realm_role_by_id(self, role_id: str) -> dict:
        """
        Get realm role by role id.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: role's id, not name!
        :type role_id: str
        :return: role
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_realm_role(self, role_name: str, payload: dict) -> bytes:
        """
        Update a role for the realm by name.

        :param role_name: The name of the role to be updated
        :type role_name: str
        :param payload: The role (use RoleRepresentation)
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def update_realm_users_profile(self, payload: dict) -> dict:
        """
        Update realm users profile for the current realm.

        :param up_config: List of attributes, groups, unmamagedAttributePolicy

        Related documentation:
        https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#UPConfig
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REALM_USER_PROFILE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_OK],
        )

    def delete_realm_role(self, role_name: str) -> bytes:
        """
        Delete a role for the realm by name.

        :param role_name: The role name
        :type role_name: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def add_composite_realm_roles_to_role(self, role_name: str, roles: str | list) -> bytes:
        """
        Add composite roles to the role.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def remove_composite_realm_roles_to_role(self, role_name: str, roles: str | list) -> bytes:
        """
        Remove composite roles from the role.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_composite_realm_roles_of_role(self, role_name: str) -> list:
        """
        Get composite roles of the role.

        :param role_name: The name of the role
        :type role_name: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles_to_client_scope(self, client_id: str, roles: str | list) -> bytes:
        """
        Assign realm roles to a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_realm_roles_of_client_scope(self, client_id: str, roles: str | list) -> bytes:
        """
        Delete realm roles of a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_realm_roles_of_client_scope(self, client_id: str) -> list:
        """
        Get all realm roles for a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_client_roles_to_client_scope(
        self,
        client_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Assign client roles to a client's dedicated scope.

        To assign roles to a client scope, use add_client_specific_roles_to_client_scope.

        :param client_id: id of client (not client-id) who is assigned the roles
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_client_roles_of_client_scope(
        self,
        client_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles of a client's dedicated scope.

        To delete roles from a client scope, use remove_client_specific_roles_of_client_scope.

        :param client_id: id of client (not client-id) who is assigned the roles
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_roles_of_client_scope(self, client_id: str, client_roles_owner_id: str) -> list:
        """
        Get all client roles for a client's dedicated scope.

        To get roles for a client scope, use get_client_specific_roles_of_client_scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles(self, user_id: str, roles: str | list) -> bytes:
        """
        Assign realm roles to a user.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_realm_roles_of_user(self, user_id: str, roles: str | list) -> bytes:
        """
        Delete realm roles of a user.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_realm_roles_of_user(self, user_id: str) -> list:
        """
        Get all realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_available_realm_roles_of_user(self, user_id: str) -> list:
        """
        Get all available (i.e. unassigned) realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_AVAILABLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_composite_realm_roles_of_user(
        self,
        user_id: str,
        brief_representation: bool = True,
    ) -> list:
        """
        Get all composite (i.e. implicit) realm roles for a user.

        :param user_id: id of user
        :type user_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_COMPOSITE.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_realm_roles(self, group_id: str, roles: str | list) -> bytes:
        """
        Assign realm roles to a group.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_group_realm_roles(self, group_id: str, roles: str | list) -> bytes:
        """
        Delete realm roles of a group.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_group_realm_roles(self, group_id: str, brief_representation: bool = True) -> list:
        """
        Get all realm roles for a group.

        :param group_id: id of the group
        :type group_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_client_roles(self, group_id: str, client_id: str, roles: str | list) -> bytes:
        """
        Assign client roles to a group.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_group_client_roles(self, group_id: str, client_id: str) -> list:
        """
        Get client roles of a group.

        :param group_id: id of group
        :type group_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_group_client_roles(self, group_id: str, client_id: str, roles: str | list) -> bytes:
        """
        Delete client roles of a group.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_all_roles_of_user(self, user_id: str) -> list:
        """
        Get all level roles for a user.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_ALL_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_roles_of_user(self, user_id: str, client_id: str) -> list:
        """
        Get all client roles for a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return self._get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES,
            user_id,
            client_id,
        )

    def get_available_client_roles_of_user(self, user_id: str, client_id: str) -> list:
        """
        Get available client role-mappings for a user.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return self._get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE,
            user_id,
            client_id,
        )

    def get_composite_client_roles_of_user(
        self,
        user_id: str,
        client_id: str,
        brief_representation: bool = False,
    ) -> list:
        """
        Get composite client role-mappings for a user.

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
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE,
            user_id,
            client_id,
            **params,
        )

    def _get_client_roles_of_user(
        self,
        client_level_role_mapping_url: str,
        user_id: str,
        client_id: str,
        **params: dict,
    ) -> list:
        """
        Get client roles of a single user helper.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_get(
            client_level_role_mapping_url.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_roles_of_user(
        self,
        user_id: str,
        client_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles from a user.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_authentication_flows(self) -> list:
        """
        Get authentication flows.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_FLOWS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authentication_flow_for_id(self, flow_id: str) -> dict:
        """
        Get one authentication flow by it's id.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: the id of a flow NOT it's alias
        :type flow_id: str
        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-id": flow_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_ALIAS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow(self, payload: dict, skip_exists: bool = False) -> bytes:
        """
        Create a new authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def update_authentication_flow(self, flow_id: str, payload: dict) -> bytes:
        """
        Update an authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: The id of the flow
        :type flow_id: str
        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"id": flow_id, "realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_FLOW.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_ACCEPTED, HTTP_NO_CONTENT],
        )

    def copy_authentication_flow(self, payload: dict, flow_alias: str) -> bytes:
        """
        Copy existing authentication flow under a new name.

        The new name is given as 'newName' attribute of the passed payload.

        :param payload: JSON containing 'newName' attribute
        :type payload: dict
        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_COPY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def delete_authentication_flow(self, flow_id: str) -> bytes:
        """
        Delete authentication flow.

        AuthenticationInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationinforepresentation

        :param flow_id: authentication flow id
        :type flow_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": flow_id}
        data_raw = self.connection.raw_delete(urls_patterns.URL_ADMIN_FLOW.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_authentication_flow_executions(self, flow_alias: str) -> list:
        """
        Get authentication flow executions.

        Returns all execution steps

        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Response(json)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authentication_flow_executions(self, payload: dict, flow_alias: str) -> bytes:
        """
        Update an authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_ACCEPTED, HTTP_NO_CONTENT],
        )

    def get_authentication_flow_execution(self, execution_id: str) -> list:
        """
        Get authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: the execution ID
        :type execution_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": execution_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow_execution(self, payload: dict, flow_alias: str) -> bytes:
        """
        Create an authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_EXECUTION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def delete_authentication_flow_execution(self, execution_id: str) -> bytes:
        """
        Delete authentication flow execution.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: keycloak client id (not oauth client-id)
        :type execution_id: str
        :return: Keycloak server response (json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": execution_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def change_execution_priority(self, execution_id: str, diff: int) -> None:
        """
        Raise or lower execution priority of diff time.

        :param execution_id: The ID of the execution
        :type execution_id: str
        :param diff: The difference in priority, positive to raise, negative to lower, the value
            is the number of times
        :type diff: int
        :raises KeycloakPostError: when post requests are failed
        """
        params_path = {"id": execution_id, "realm-name": self.connection.realm_name}
        if diff > 0:
            for _ in range(diff):
                data_raw = self.connection.raw_post(
                    urls_patterns.URL_AUTHENTICATION_EXECUTION_RAISE_PRIORITY.format(
                        **params_path,
                    ),
                    data="{}",
                )
                raise_error_from_response(
                    data_raw,
                    KeycloakPostError,
                    expected_codes=[HTTP_NO_CONTENT],
                )
        elif diff < 0:
            for _ in range(-diff):
                data_raw = self.connection.raw_post(
                    urls_patterns.URL_AUTHENTICATION_EXECUTION_LOWER_PRIORITY.format(
                        **params_path,
                    ),
                    data="{}",
                )
                raise_error_from_response(
                    data_raw,
                    KeycloakPostError,
                    expected_codes=[HTTP_NO_CONTENT],
                )

    def create_authentication_flow_subflow(
        self,
        payload: dict,
        flow_alias: str,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create a new sub authentication flow for a given authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_FLOW.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    def get_authenticator_providers(self) -> list:
        """
        Get authenticator providers list.

        :return: Authenticator providers
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_PROVIDERS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authenticator_provider_config_description(self, provider_id: str) -> dict:
        """
        Get authenticator's provider configuration description.

        AuthenticatorConfigInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfiginforepresentation

        :param provider_id: Provider Id
        :type provider_id: str
        :return: AuthenticatorConfigInfoRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "provider-id": provider_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG_DESCRIPTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authenticator_config(self, config_id: str) -> dict:
        """
        Get authenticator configuration.

        Returns all configuration details.

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_execution_config(self, execution_id: str, payload: dict) -> bytes:
        """
        Update execution with new configuration.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfigrepresentation

        :param execution_id: The ID of the execution
        :type execution_id: str
        :param payload: Configuration to add to the execution
        :type payload: dir
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"id": execution_id, "realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def update_authenticator_config(self, payload: dict, config_id: str) -> bytes:
        """
        Update an authenticator configuration.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfigrepresentation

        :param payload: AuthenticatorConfigRepresentation
        :type payload: dict
        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_authenticator_config(self, config_id: str) -> bytes:
        """
        Delete a authenticator configuration.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authentication_management_resource

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def sync_users(self, storage_id: str, action: str) -> bytes:
        """
        Trigger user sync from provider.

        :param storage_id: The id of the user storage provider
        :type storage_id: str
        :param action: Action can be "triggerFullSync" or "triggerChangedUsersSync"
        :type action: str
        :return: Keycloak server response
        :rtype: bytes
        """
        data = {"action": action}
        params_query = {"action": action}

        params_path = {"realm-name": self.connection.realm_name, "id": storage_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_USER_STORAGE.format(**params_path),
            data=json.dumps(data),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_scopes(self) -> list:
        """
        Get client scopes.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

        :return: Keycloak server response Array of (ClientScopeRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope(self, client_scope_id: str) -> dict:
        """
        Get client scope.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope_by_name(self, client_scope_name: str) -> dict:
        """
        Get client scope by name.

        Get representation of the client scope identified by the client scope name.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes
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

    def create_client_scope(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

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

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def update_client_scope(self, client_scope_id: str, payload: dict) -> bytes:
        """
        Update a client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ClientScopeRepresentation
        :type payload: dict
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_client_scope(self, client_scope_id: str) -> bytes:
        """
        Delete existing client scope.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_mappers_from_client_scope(self, client_scope_id: str) -> list:
        """
        Get a list of all mappers connected to the client scope.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource
        :param client_scope_id: Client scope id
        :type client_scope_id: str
        :returns: Keycloak server response (ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def add_mapper_to_client_scope(self, client_scope_id: str, payload: dict) -> bytes:
        """
        Add a mapper to a client scope.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_create_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def delete_mapper_from_client_scope(
        self,
        client_scope_id: str,
        protocol_mapper_id: str,
    ) -> bytes:
        """
        Delete a mapper from a client scope.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_delete_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param protocol_mapper_id: Protocol mapper id
        :type protocol_mapper_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def update_mapper_in_client_scope(
        self,
        client_scope_id: str,
        protocol_mapper_id: str,
        payload: dict,
    ) -> bytes:
        """
        Update an existing protocol mapper in a client scope.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource

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
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_default_default_client_scopes(self) -> list:
        """
        Get default default client scopes.

        Return list of default default client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_default_default_client_scope(self, scope_id: str) -> bytes:
        """
        Delete default default client scope.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def add_default_default_client_scope(self, scope_id: str) -> bytes:
        """
        Add default default client scope.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        payload = {"realm": self.connection.realm_name, "clientScopeId": scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_default_optional_client_scopes(self) -> list:
        """
        Get default optional client scopes.

        Return list of default optional client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_default_optional_client_scope(self, scope_id: str) -> bytes:
        """
        Delete default optional client scope.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def add_default_optional_client_scope(self, scope_id: str) -> bytes:
        """
        Add default optional client scope.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        payload = {"realm": self.connection.realm_name, "clientScopeId": scope_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def add_client_specific_roles_to_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Assign client roles to a client scope.

        To assign roles to a client's dedicated scope, use assign_client_roles_to_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation, must include id and name)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def remove_client_specific_roles_of_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles of a client scope.

        To delete roles from a client's dedicated scope, use delete_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation, must include id and name)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_specific_roles_of_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
    ) -> list:
        """
        Get client roles for a client scope, for a specific client.

        To get roles for a client's dedicated scope, use get_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_all_roles_of_client_scope(self, client_scope_id: str) -> list:
        """
        Get all client roles for a client scope.

        To get roles for a client's dedicated scope,
        use get_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_mappers_from_client(self, client_id: str) -> list:
        """
        List of all client mappers.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocolmapperrepresentation

        :param client_id: Client id
        :type client_id: str
        :returns: KeycloakServerResponse (list of ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    def add_mapper_to_client(self, client_id: str, payload: dict) -> bytes:
        """
        Add a mapper to a client.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_create_mapper

        :param client_id: The id of the client
        :type client_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def update_client_mapper(self, client_id: str, mapper_id: str, payload: dict) -> bytes:
        """
        Update client mapper.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "protocol-mapper-id": mapper_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def remove_client_mapper(self, client_id: str, client_mapper_id: str) -> bytes:
        """
        Remove a mapper from the client.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource

        :param client_id: The id of the client
        :type client_id: str
        :param client_mapper_id: The id of the mapper to be deleted
        :type client_mapper_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "protocol-mapper-id": client_mapper_id,
        }
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def generate_client_secrets(self, client_id: str) -> bytes:
        """
        Generate a new secret for the client.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_regeneratesecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path),
            data=None,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_client_secrets(self, client_id: str) -> dict:
        """
        Get representation of the client secrets.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientsecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_components(self, query: dict | None = None) -> list:
        """
        Get components.

        Return a list of components, filtered according to query parameters

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: components list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_component(self, payload: dict) -> str:
        """
        Create a new component.

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param payload: ComponentRepresentation
        :type payload: dict
        :return: Component id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    def get_component(self, component_id: str) -> dict:
        """
        Get representation of the component.

        :param component_id: Component id

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param component_id: Id of the component
        :type component_id: str
        :return: ComponentRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_get(urls_patterns.URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_component(self, component_id: str, payload: dict) -> bytes:
        """
        Update the component.

        :param component_id: Component id
        :type component_id: str
        :param payload: ComponentRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def delete_component(self, component_id: str) -> bytes:
        """
        Delete the component.

        :param component_id: Component id
        :type component_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_keys(self) -> list:
        """
        Get keys.

        Return a list of keys, filtered according to query parameters

        KeysMetadataRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_key_resource

        :return: keys list
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_KEYS.format(**params_path),
            data=None,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_admin_events(self, query: dict | None = None) -> list:
        """
        Get Administrative events.

        Return a list of events, filtered according to query parameters

        AdminEvents Representation array
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getevents
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_get_adminrealmsrealmadmin_events

        :param query: Additional query parameters
        :type query: dict
        :return: events list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_ADMIN_EVENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_events(self, query: dict | None = None) -> list:
        """
        Get events.

        Return a list of events, filtered according to query parameters

        EventRepresentation array
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_eventrepresentation

        :param query: Additional query parameters
        :type query: dict
        :return: events list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_USER_EVENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def set_events(self, payload: dict) -> bytes:
        """
        Set realm events configuration.

        RealmEventsConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmeventsconfigrepresentation

        :param payload: Payload object for the events configuration
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_EVENTS_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def get_client_all_sessions(self, client_id: str, query: dict | None = None) -> list:
        """
        Get sessions associated with the client.

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_usersessionrepresentation

        :param client_id: id of client
        :type client_id: str
        :param query: Additional query parameters
        :type query: dict
        :return: UserSessionRepresentation
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_ALL_SESSIONS.format(**params_path)
        if "first" in query or "max" in query:
            return self.__fetch_paginated(url, query)

        return self.__fetch_all(url, query)

    def get_client_sessions_stats(self) -> dict:
        """
        Get current session count for all clients with active sessions.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientsessionstats

        :return: Dict of clients and session count
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SESSION_STATS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_management_permissions(self, client_id: str) -> list:
        """
        Get management permissions for a client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_client_management_permissions(self, payload: dict, client_id: str) -> bytes:
        """
        Update management permissions for a client.

        ManagementPermissionReference
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_managementpermissionreference

        Payload example::

            payload={
                "enabled": true
            }

        :param payload: ManagementPermissionReference
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_OK])

    def get_client_authz_policy_scopes(self, client_id: str, policy_id: str) -> list:
        """
        Get scopes for a given policy.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_policy_resources(self, client_id: str, policy_id: str) -> list:
        """
        Get resources for a given policy.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_RESOURCES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_authz_scope_permission(self, client_id: str, scope_id: str) -> list:
        """
        Get permissions for a given scope.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "scope-id": scope_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_authz_scope_permission(self, payload: dict, client_id: str) -> bytes:
        """
        Create permissions for a authz scope.

        Payload example::

            payload={
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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_ADD_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def update_client_authz_scope_permission(
        self,
        payload: dict,
        client_id: str,
        scope_id: str,
    ) -> bytes:
        """
        Update permissions for a given scope.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "scope-id": scope_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_CREATED])

    def update_client_authz_resource_permission(
        self,
        payload: dict,
        client_id: str,
        resource_id: str,
    ) -> bytes:
        """
        Update permissions for a given resource.

        Payload example::

            payload={
                "id": resource_id,
                "name": "My Permission Name",
                "type": "resource",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "resources": [some_resource_id],
                "scopes": [],
                "policies": [some_policy_id],
            }

        :param payload: No Document
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: No Document
        :type resource_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_CREATED])

    def get_client_authz_client_policies(self, client_id: str) -> list:
        """
        Get policies for a given client.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def get_client_authz_permission_associated_policies(
        self,
        client_id: str,
        policy_id: str,
    ) -> list:
        """
        Get associated policies for a given client permission.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_POLICIES.format(
                **params_path,
            ),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    def create_client_authz_client_policy(self, payload: dict, client_id: str) -> bytes:
        """
        Create a new policy for a given client.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    def get_composite_client_roles_of_group(
        self,
        client_id: str,
        group_id: str,
        brief_representation: bool = True,
    ) -> list:
        """
        Get the composite client roles of the given group for the given client.

        :param client_id: id of the client.
        :type client_id: str
        :param group_id: id of the group.
        :type group_id: str
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: the composite client roles of the group (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        params = {"briefRepresentation": brief_representation}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES_COMPOSITE.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_role_client_level_children(self, client_id: str, role_id: str) -> list:
        """
        Get the child roles of which the given composite client role is composed of.

        :param client_id: id of the client.
        :type client_id: str
        :param role_id: id of the role.
        :type role_id: str
        :return: the child roles (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": role_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_CHILDREN.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def upload_certificate(self, client_id: str, certcont: str) -> dict:
        """
        Upload a new certificate for the client.

        :param client_id: id of the client.
        :type client_id: str
        :param certcont: the content of the certificate.
        :type certcont: str
        :return: dictionary {"certificate": "<certcont>"},
                 where <certcont> is the content of the uploaded certificate.
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "attr": "jwt.credential",
        }
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

    def get_required_action_by_alias(self, action_alias: str) -> dict | None:
        """
        Get a required action by its alias.

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

    def get_required_actions(self) -> list:
        """
        Get the required actions for the realms.

        :return: the required actions (list of RequiredActionProviderRepresentation).
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_required_action(self, action_alias: str, payload: dict) -> dict:
        """
        Update a required action.

        :param action_alias: the action alias.
        :type action_alias: str
        :param payload: the new required action (RequiredActionProviderRepresentation).
        :type payload: dict
        :return: empty dictionary.
        :rtype: dict
        """
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        params_path = {"realm-name": self.connection.realm_name, "action-alias": action_alias}
        data_raw = self.connection.raw_put(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS_ALIAS.format(**params_path),
            data=payload,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def get_bruteforce_detection_status(self, user_id: str) -> dict:
        """
        Get bruteforce detection status for user.

        :param user_id: User id
        :type user_id: str
        :return: Bruteforce status.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_get(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def clear_bruteforce_attempts_for_user(self, user_id: str) -> dict:
        """
        Clear bruteforce attempts for user.

        :param user_id: User id
        :type user_id: str
        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def clear_all_bruteforce_attempts(self) -> dict:
        """
        Clear bruteforce attempts for all users in realm.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def clear_keys_cache(self) -> dict:
        """
        Clear keys cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_KEYS_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def clear_realm_cache(self) -> dict:
        """
        Clear realm cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_REALM_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    def clear_user_cache(self) -> dict:
        """
        Clear user cache.

        :return: empty dictionary.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_post(
            urls_patterns.URL_ADMIN_CLEAR_USER_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    # async functions start
    async def a___fetch_all(self, url: str, query: dict | None = None) -> list:
        """
        Paginate asynchronously over get requests .

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
                await self.connection.a_raw_get(url, **query),
                KeycloakGetError,
            )
            if not partial_results:
                break
            results.extend(partial_results)
            if len(partial_results) < query["max"]:
                break
            page += 1
        return results

    async def a___fetch_paginated(self, url: str, query: dict | None = None) -> list:
        """
        Make a specific paginated request asynchronously.

        :param url: The url on which the query is executed
        :type url: str
        :param query: Pagination settings
        :type query: dict
        :returns: Response
        :rtype: list
        """
        query = query or {}
        return raise_error_from_response(
            await self.connection.a_raw_get(url, **query),
            KeycloakGetError,
        )

    async def a_get_current_realm(self) -> str:
        """
        Return the currently configured realm asynchronously.

        :returns: Currently configured realm name
        :rtype: str
        """
        return self.connection.realm_name

    async def a_change_current_realm(self, realm_name: str) -> None:
        """
        Change the current realm asynchronously.

        :param realm_name: The name of the realm to be configured as current
        :type realm_name: str
        """
        self.connection.realm_name = realm_name

    async def a_import_realm(self, payload: dict) -> dict:
        """
        Import a new realm asynchronously from a RealmRepresentation.

        Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :return: RealmRepresentation
        :rtype: dict
        """
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALMS,
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_partial_import_realm(self, realm_name: str, payload: dict) -> dict:
        """
        Partial import realm configuration asynchronously from PartialImportRepresentation.

        Realm partialImport is used for modifying configuration of existing realm.

        PartialImportRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_partialimportrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: PartialImportRepresentation
        :type payload: dict

        :return: PartialImportResponse
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALM_PARTIAL_IMPORT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    async def a_export_realm(
        self,
        export_clients: bool = False,
        export_groups_and_role: bool = False,
    ) -> dict:
        """
        Export the realm configurations asynchronously in the json format.

        RealmRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_partialexport

        :param export_clients: Skip if not want to export realm clients
        :type export_clients: bool
        :param export_groups_and_role: Skip if not want to export realm groups and roles
        :type export_groups_and_role: bool

        :return: realm configurations JSON
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "export-clients": export_clients,
            "export-groups-and-roles": export_groups_and_role,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALM_EXPORT.format(**params_path),
            data="",
            exportClients=export_clients,
            exportGroupsAndRoles=export_groups_and_role,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    async def a_get_realms(self) -> list:
        """
        List all realms in asynchronouslyKeycloak deployment.

        :return: realms list
        :rtype: list
        """
        data_raw = await self.connection.a_raw_get(urls_patterns.URL_ADMIN_REALMS)
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_realm(self, realm_name: str) -> dict:
        """
        Get a specific realm asynchronously.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: RealmRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_create_realm(self, payload: dict, skip_exists: bool = False) -> dict:
        """
        Create a realm asynchronously.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :type payload: dict
        :param skip_exists: Skip if Realm already exist.
        :type skip_exists: bool
        :return: Keycloak server response (RealmRepresentation)
        :rtype: dict
        """
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALMS,
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED]
            + ([HTTP_BAD_REQUEST, HTTP_CONFLICT] if skip_exists else []),
        )

    async def a_update_realm(self, realm_name: str, payload: dict) -> dict:
        """
        Update a realm asynchronously.

        This will only update top level attributes and will ignore any user,
        role, or client information in the payload.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: RealmRepresentation
        :type payload: dict
        :return: Http response
        :rtype: dict
        """
        params_path = {"realm-name": realm_name}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_REALM.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_update_realm_users_profile(self, payload: dict) -> dict:
        """
        Update realm users profile for the current realm.

        :param up_config: List of attributes, groups, unmamagedAttributePolicy

        Related documentation:
        https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#UPConfig
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_REALM_USER_PROFILE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_OK],
        )

    async def a_delete_realm(self, realm_name: str) -> bytes:
        """
        Delete a realm asynchronously.

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": realm_name}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_REALM.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_users(self, query: dict | None = None) -> list:
        """
        Get all users asynchronously.

        Return a list of users, filtered according to query parameters

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: users list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_USERS.format(**params_path)

        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    async def a_create_idp(self, payload: dict) -> dict:
        """
        Create an ID Provider asynchronously.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :param: payload: IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_IDPS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_update_idp(self, idp_alias: str, payload: dict) -> bytes:
        """
        Update an ID Provider asynchronously.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identity_providers_resource

        :param: idp_alias: alias for IdP to update
        :type idp_alias: str
        :param: payload: The IdentityProviderRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_IDP.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_add_mapper_to_idp(self, idp_alias: str, payload: dict) -> dict:
        """
        Create an ID Provider asynchronously.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityprovidermapperrepresentation

        :param: idp_alias: alias for Idp to add mapper in
        :type idp_alias: str
        :param: payload: IdentityProviderMapperRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "idp-alias": idp_alias}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_update_mapper_in_idp(self, idp_alias: str, mapper_id: str, payload: dict) -> bytes:
        """
        Update an IdP mapper asynchronously.

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_update

        :param: idp_alias: alias for Idp to fetch mappers
        :type idp_alias: str
        :param: mapper_id: Mapper Id to update
        :type mapper_id: str
        :param: payload: IdentityProviderMapperRepresentation
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "idp-alias": idp_alias,
            "mapper-id": mapper_id,
        }

        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_IDP_MAPPER_UPDATE.format(**params_path),
            data=json.dumps(payload),
        )

        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_idp_mappers(self, idp_alias: str) -> list:
        """
        Get IDP mappers asynchronously.

        Returns a list of ID Providers mappers

        IdentityProviderMapperRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getmappers

        :param: idp_alias: alias for Idp to fetch mappers
        :type idp_alias: str
        :return: array IdentityProviderMapperRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "idp-alias": idp_alias}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_idps(self) -> list:
        """
        Get IDPs asynchronously.

        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_IDPS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_idp(self, idp_alias: str) -> dict:
        """
        Get IDP provider asynchronously.

        Get the representation of a specific IDP Provider.

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_identityproviderrepresentation

        :param: idp_alias: alias for IdP to get
        :type idp_alias: str
        :return: IdentityProviderRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_IDP.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_idp(self, idp_alias: str) -> dict:
        """
        Delete an ID Provider asynchronously.

        :param: idp_alias: idp alias name
        :type idp_alias: str
        :returns: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "alias": idp_alias}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_IDP.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_create_user(self, payload: dict, exist_ok: bool = False) -> str:
        """
        Create a new user asynchronously.

        Username must be unique

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation
        :type payload: dict
        :param exist_ok: If False, raise KeycloakGetError if username already exists.
            Otherwise, return existing user ID.
        :type exist_ok: bool

        :return: user_id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}

        if exist_ok:
            exists = await self.a_get_user_id(username=payload["username"])

            if exists is not None:
                return str(exists)

        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USERS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_users_count(self, query: dict | None = None) -> int:
        """
        Count users asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_users_resource

        :param query: (dict) Query parameters for users count
        :type query: dict

        :return: counter
        :rtype: int
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USERS_COUNT.format(**params_path),
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_user_id(self, username: str) -> str:
        """
        Get internal keycloak user id from username asynchronously.

        This is required for further actions against this user.

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation
        :type username: str

        :return: user_id
        :rtype: str
        """
        lower_user_name = username.lower()
        users = await self.a_get_users(
            query={"username": lower_user_name, "max": 1, "exact": True},
        )
        return users[0]["id"] if len(users) == 1 else None

    async def a_get_user(self, user_id: str, user_profile_metadata: bool = False) -> dict:
        """
        Get representation of the user asynchronously.

        UserRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userrepresentation

        :param user_id: User id
        :type user_id: str
        :param user_profile_metadata: whether to include user profile metadata in the response
        :type user_profile_metadata: bool
        :return: UserRepresentation
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER.format(**params_path),
            userProfileMetadata=user_profile_metadata,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_user_groups(
        self,
        user_id: str,
        query: dict | None = None,
        brief_representation: bool = True,
    ) -> list:
        """
        Get user groups asynchronously.

        Returns a list of groups of which the user is a member

        :param user_id: User id
        :type user_id: str
        :param query: Additional query options
        :type query: dict
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: user groups list
        :rtype: list
        """
        query = query or {}
        params = {"briefRepresentation": brief_representation}
        query.update(params)

        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        url = urls_patterns.URL_ADMIN_USER_GROUPS.format(**params_path)
        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    async def a_update_user(self, user_id: str, payload: dict) -> bytes:
        """
        Update the user asynchronously.

        :param user_id: User id
        :type user_id: str
        :param payload: UserRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_USER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_disable_user(self, user_id: str) -> bytes:
        """
        Disable the user asynchronously from the realm. Disabled users can not log in.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return await self.a_update_user(user_id=user_id, payload={"enabled": False})

    async def a_enable_user(self, user_id: str) -> bytes:
        """
        Enable the user from the realm asynchronously.

        :param user_id: User id
        :type user_id: str

        :return: Http response
        :rtype: bytes
        """
        return await self.a_update_user(user_id=user_id, payload={"enabled": True})

    async def a_disable_all_users(self) -> None:
        """Disable all existing users asynchronously."""
        users = await self.a_get_users()
        for user in users:
            user_id = user["id"]
            await self.a_disable_user(user_id=user_id)

    async def a_enable_all_users(self) -> None:
        """Disable all existing users asynchronously."""
        users = await self.a_get_users()
        for user in users:
            user_id = user["id"]
            await self.a_enable_user(user_id=user_id)

    async def a_delete_user(self, user_id: str) -> bytes:
        """
        Delete the user asynchronously.

        :param user_id: User id
        :type user_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_set_user_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = True,
    ) -> bytes:
        """
        Set up a password for the user asynchronously.

        If temporary is True, the user will have to reset
        the temporary password next time they log in.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_users_resource
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_credentialrepresentation

        :param user_id: User id
        :type user_id: str
        :param password: New password
        :type password: str
        :param temporary: True if password is temporary
        :type temporary: bool
        :returns: Response
        :rtype: bytes
        """
        payload = {"type": "password", "temporary": temporary, "value": password}
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_RESET_PASSWORD.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_credentials(self, user_id: str) -> list:
        """
        Get user credentials asynchronously.

        Returns a list of credential belonging to the user.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :returns: Keycloak server response (CredentialRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_CREDENTIALS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_credential(self, user_id: str, credential_id: str) -> bytes:
        """
        Delete credential of the user asynchronously.

        CredentialRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_credentialrepresentation

        :param: user_id: user id
        :type user_id: str
        :param: credential_id: credential id
        :type credential_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "credential_id": credential_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_CREDENTIAL.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_user_logout(self, user_id: str) -> bytes:
        """
        Log out the user.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_logout

        :param user_id: User id
        :type user_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USER_LOGOUT.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_user_consents(self, user_id: str) -> list:
        """
        Asynchronously get consents granted by the user.

        UserConsentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_userconsentrepresentation

        :param user_id: User id
        :type user_id: str
        :returns: List of UserConsentRepresentations
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_CONSENTS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_revoke_consent(self, user_id: str, client_id: str) -> dict | bytes:
        """
        Asynchronously revoke consent and offline tokens for particular client from user.

        :param user_id: User id
        :type user_id: str
        :param client_id: Client id
        :type client_id: str

        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_CONSENT.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_user_social_logins(self, user_id: str) -> list:
        """
        Get user social logins asynchronously.

        Returns a list of federated identities/social logins of which the user has been associated
        with
        :param user_id: User id
        :type user_id: str
        :returns: Federated identities list
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITIES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_add_user_social_login(
        self,
        user_id: str,
        provider_id: str,
        provider_userid: str,
        provider_username: str,
    ) -> bytes:
        """
        Add a federated identity / social login provider asynchronously to the user.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "provider": provider_id,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED, HTTP_NO_CONTENT],
        )

    async def a_delete_user_social_login(self, user_id: str, provider_id: str) -> bytes:
        """
        Delete a federated identity / social login provider asynchronously from the user.

        :param user_id: User id
        :type user_id: str
        :param provider_id: Social login provider id
        :type provider_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "provider": provider_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_send_update_account(
        self,
        user_id: str,
        payload: dict,
        client_id: str | None = None,
        lifespan: int | None = None,
        redirect_uri: str | None = None,
    ) -> bytes:
        """
        Send an update account email to the user asynchronously.

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
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
            data=json.dumps(payload),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_send_verify_email(
        self,
        user_id: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> bytes:
        """
        Send a update account email to the user asynchronously.

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
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redirect_uri": redirect_uri}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
            data={},
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_get_sessions(self, user_id: str) -> list:
        """
        Get sessions associated with the user asynchronously.

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_usersessionrepresentation

        :param user_id: Id of user
        :type user_id: str
        :return: UserSessionRepresentation
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GET_SESSIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_server_info(self) -> dict:
        """
        Get themes, social providers, etc. on this server asynchronously.

        ServerInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        :rtype: dict
        """
        data_raw = await self.connection.a_raw_get(urls_patterns.URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_groups(self, query: dict | None = None, full_hierarchy: bool = False) -> list:
        """
        Get groups asynchronously.

        Returns a list of groups belonging to the realm

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        Notice that when using full_hierarchy=True, the response will be a nested structure
        containing all the children groups. If used with query parameters, the full_hierarchy
        will be applied to the received groups only.

        :param query: Additional query options
        :type query: dict
        :param full_hierarchy: If True, return all of the nested children groups, otherwise only
            the first level children are returned
        :type full_hierarchy: bool
        :return: array GroupRepresentation
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        url = urls_patterns.URL_ADMIN_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            groups = await self.a___fetch_paginated(url, query)
        else:
            groups = await self.a___fetch_all(url, query)

        # For version +23.0.0
        for group in groups:
            if group.get("subGroupCount"):
                group["subGroups"] = await self.a_get_group_children(
                    group_id=group.get("id"),
                    full_hierarchy=full_hierarchy,
                )

        return groups

    async def a_get_group(self, group_id: str, full_hierarchy: bool = False) -> dict:
        """
        Get group by id asynchronously.

        Returns full group details

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param group_id: The group id
        :type group_id: str
        :param full_hierarchy: If True, return all of the nested children groups, otherwise only
            the first level children are returned
        :type full_hierarchy: bool
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        response = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUP.format(**params_path),
        )

        if response.status_code >= HTTP_BAD_REQUEST:
            return raise_error_from_response(response, KeycloakGetError)

        # For version +23.0.0
        group = response.json()
        if group.get("subGroupCount"):
            group["subGroups"] = await self.a_get_group_children(
                group.get("id"),
                full_hierarchy=full_hierarchy,
            )

        return group

    async def a_get_subgroups(self, group: str, path: str) -> dict | None:
        """
        Get subgroups asynchronously.

        Utility function to iterate through nested group structures

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

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
            if subgroup["subGroups"]:
                for _subgroup in group["subGroups"]:
                    result = await self.a_get_subgroups(_subgroup, path)
                    if result:
                        return result
        # went through the tree without hits
        return None

    async def a_get_group_children(
        self,
        group_id: str,
        query: dict | None = None,
        full_hierarchy: bool = False,
    ) -> list:
        """
        Get group children by parent id asynchronously.

        Returns full group children details

        :param group_id: The parent group id
        :type group_id: str
        :param query: Additional query options
        :type query: dict
        :param full_hierarchy: If True, return all of the nested children groups
        :type full_hierarchy: bool
        :return: Keycloak server response (GroupRepresentation)
        :rtype: list
        :raises ValueError: If both query and full_hierarchy parameters are used
        """
        query = query or {}
        if query and full_hierarchy:
            msg = "Cannot use both query and full_hierarchy parameters"
            raise ValueError(msg)

        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        url = urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path)
        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)
        res = await self.a___fetch_all(url, query)

        if not full_hierarchy:
            return res

        for group in res:
            if group.get("subGroupCount"):
                group["subGroups"] = await self.a_get_group_children(
                    group_id=group.get("id"),
                    full_hierarchy=full_hierarchy,
                )

        return res

    async def a_get_group_members(self, group_id: str, query: dict | None = None) -> list:
        """
        Get members by group id asynchronously.

        Returns group members

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_userrepresentation

        :param group_id: The group id
        :type group_id: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getmembers)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        url = urls_patterns.URL_ADMIN_GROUP_MEMBERS.format(**params_path)

        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    async def a_get_group_by_path(self, path: str) -> dict:
        """
        Get group id based on name or path asynchronously .

        Returns full group details for a group defined by path

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param path: group path
        :type path: str
        :return: Keycloak server response (GroupRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "path": path}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUP_BY_PATH.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, [HTTP_OK, 404])

    async def a_create_group(
        self,
        payload: dict,
        parent: str | None = None,
        skip_exists: bool = False,
    ) -> str | None:
        """
        Create a group in the Realm asynchronously.

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

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
            params_path = {"realm-name": self.connection.realm_name}
            data_raw = await self.connection.a_raw_post(
                urls_patterns.URL_ADMIN_GROUPS.format(**params_path),
                data=json.dumps(payload),
            )
        else:
            params_path = {"realm-name": self.connection.realm_name, "id": parent}
            data_raw = await self.connection.a_raw_post(
                urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path),
                data=json.dumps(payload),
            )

        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        try:
            _last_slash_idx = data_raw.headers["Location"].rindex("/")
            return data_raw.headers["Location"][_last_slash_idx + 1 :]
        except KeyError:
            return None

    async def a_update_group(self, group_id: str, payload: dict) -> bytes:
        """
        Update group, ignores subgroups asynchronously.

        GroupRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/#_grouprepresentation

        :param group_id: id of group
        :type group_id: str
        :param payload: GroupRepresentation with updated information.
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_GROUP.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_groups_count(self, query: dict | None = None) -> dict:
        """
        Count groups asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_groups

        :param query: (dict) Query parameters for groups count
        :type query: dict

        :return: Keycloak Server Response
        :rtype: dict
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUPS_COUNT.format(**params_path),
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_group_set_permissions(self, group_id: str, enabled: bool = True) -> bytes:
        """
        Enable/Disable permissions for a group asynchronously.

        Cannot delete group if disabled

        :param group_id: id of group
        :type group_id: str
        :param enabled: Enabled flag
        :type enabled: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
            data=json.dumps({"enabled": enabled}),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_group_user_add(self, user_id: str, group_id: str) -> bytes:
        """
        Add user to group (user_id and group_id) asynchronously.

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to add to
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "group-id": group_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path),
            data=None,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_group_user_remove(self, user_id: str, group_id: str) -> bytes:
        """
        Remove user from group (user_id and group_id) asynchronously.

        :param user_id:  id of user
        :type user_id: str
        :param group_id:  id of group to remove from
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "group-id": group_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_group(self, group_id: str) -> bytes:
        """
        Delete a group in the Realm asynchronously.

        :param group_id:  id of group to delete
        :type group_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_GROUP.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_clients(self) -> list:
        """
        Get clients asynchronously.

        Returns a list of clients belonging to the realm

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client(self, client_id: str) -> dict:
        """
        Get representation of the client asynchronously.

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_id(self, client_id: str) -> str | None:
        """
        Get internal keycloak client id from client-id asynchronously.

        This is required for further actions against this client.

        :param client_id: clientId in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: client_id (uuid as string)
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
            clientId=client_id,
        )
        data_response = raise_error_from_response(data_raw, KeycloakGetError)

        for client in data_response:
            if client_id == client.get("clientId"):
                return client["id"]

        return None

    async def a_get_client_authz_settings(self, client_id: str) -> dict:
        """
        Get authorization json from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_client_authz_resource(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes | dict:
        """
        Create resources of client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type payload: dict
        :param skip_exists: Skip the creation in case the resource exists
        :type skip_exists: bool

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}

        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_update_client_authz_resource(
        self,
        client_id: str,
        resource_id: str,
        payload: dict,
    ) -> bytes:
        """
        Update resource of client asynchronously.

        Any parameter missing from the ResourceRepresentation in the payload WILL be set
        to default by the Keycloak server.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_client_authz_resource(self, client_id: str, resource_id: str) -> bytes:
        """
        Delete a client resource asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_authz_resources(self, client_id: str) -> list:
        """
        Get resources from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (ResourceRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_authz_resource(self, client_id: str, resource_id: str) -> dict:
        """
        Get a client resource asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: id in ResourceRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_resourcerepresentation
        :type resource_id: str

        :return: Keycloak server response (ResourceRepresentation)
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_create_client_authz_role_based_policy(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create role-based policy of client asynchronously.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: No Document
        :type payload: dict
        :param skip_exists: Skip creation in case the object exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_create_client_authz_policy(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create an authz policy of client asynchronously.

        Payload example::

            payload={
                "name": "Policy-time-based",
                "type": "time",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {
                    "hourEnd": "18",
                    "hour": "9"
                }
            }

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: No Document
        :type payload: dict
        :param skip_exists: Skip creation in case the object exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
            permission=False,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_create_client_authz_resource_based_permission(
        self,
        client_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create resource-based permission of client asynchronously.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param payload: PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type payload: dict
        :param skip_exists: Skip creation in case the object already exists
        :type skip_exists: bool
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_get_client_authz_scopes(self, client_id: str) -> list:
        """
        Get scopes from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_client_authz_scopes(self, client_id: str, payload: dict) -> bytes:
        """
        Create scopes for client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :param payload: ScopeRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_ScopeRepresentation
        :type payload: dict
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPES.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_get_client_authz_permissions(self, client_id: str) -> list:
        """
        Get permissions from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_PERMISSIONS.format(**params_path),
            max=-1,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_authz_policies(self, client_id: str) -> list:
        """
        Get policies from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path),
            max=-1,
            permission=False,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_client_authz_policy(self, client_id: str, policy_id: str) -> bytes:
        """
        Delete a policy from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_authz_policy(self, client_id: str, policy_id: str) -> dict:
        """
        Get a policy from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_service_account_user(self, client_id: str) -> dict:
        """
        Get service account user from client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: UserRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_default_client_scopes(self, client_id: str) -> list:
        """
        Get all default client scopes from client asynchronously.

        :param client_id: id of the client in which the new default client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_add_client_default_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
        payload: dict,
    ) -> bytes:
        """
        Add a client scope to the default client scopes from client asynchronously.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_delete_client_default_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
    ) -> bytes:
        """
        Delete a client scope from the default client scopes of the client asynchronously.

        :param client_id: id of the client in which the default client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_DEFAULT_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_get_client_optional_client_scopes(self, client_id: str) -> list:
        """
        Get all optional client scopes from client asynchronously.

        :param client_id: id of the client in which the new optional client scope should be added
        :type client_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_add_client_optional_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
        payload: dict,
    ) -> bytes:
        """
        Add a client scope to the optional client scopes from client asynchronously.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_delete_client_optional_client_scope(
        self,
        client_id: str,
        client_scope_id: str,
    ) -> bytes:
        """
        Delete a client scope from the optional client scopes of the client asynchronously.

        :param client_id: id of the client in which the optional client scope should be deleted
        :type client_id: str
        :param client_scope_id: id of the client scope that should be deleted
        :type client_scope_id: str

        :return: list of client scopes with id and name
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client_scope_id": client_scope_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_create_initial_access_token(
        self,
        count: int = 1,
        expiration: int = 1,
    ) -> dict | bytes:
        """
        Create an initial access token asynchronously.

        :param count: Number of clients that can be registered
        :type count: int
        :param expiration: Days until expireation
        :type expiration: int
        :return: initial access token
        :rtype: dict
        """
        payload = {"count": count, "expiration": expiration}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_INITIAL_ACCESS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    async def a_create_client(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a client asynchronously.

        ClientRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :param skip_exists: If true then do not raise an error if client already exists
        :type skip_exists: bool
        :param payload: ClientRepresentation
        :type payload: dict
        :return: Client ID
        :rtype: str
        """
        if skip_exists:
            client_id = await self.a_get_client_id(client_id=payload["clientId"])

            if client_id is not None:
                return client_id

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_update_client(self, client_id: str, payload: dict) -> bytes:
        """
        Update a client asynchronously.

        :param client_id: Client id
        :type client_id: str
        :param payload: ClientRepresentation
        :type payload: dict

        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_client(self, client_id: str) -> bytes:
        """
        Get representation of the client asynchronously.

        ClientRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_installation_provider(self, client_id: str, provider_id: str) -> list:
        """
        Get content for given installation provider asynchronously.

        Related documentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource

        Possible provider_id list available in the ServerInfoRepresentation#clientInstallations
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_serverinforepresentation

        :param client_id: Client id
        :type client_id: str
        :param provider_id: provider id to specify response format
        :type provider_id: str
        :returns: Installation providers
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "provider-id": provider_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_INSTALLATION_PROVIDER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_get_realm_users_profile(self) -> dict:
        """
        Get list of attributes and group for given realm.

        Related documentation:
        https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#_get_adminrealmsrealmusersprofile

        Return https://www.keycloak.org/docs-api/26.0.0/rest-api/index.html#UPConfig
        :returns: UPConfig

        """
        params_path = {"realm-name": self.connection.realm_name}

        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_USER_PROFILE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_get_realm_roles(
        self, brief_representation: bool = True, search_text: str = "", query: dict | None = None
    ) -> list:
        """
        Get all roles for the realm or client asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :param search_text: optional search text to limit the returned result.
        :type search_text: str
        :param query: Query parameters (optional)
        :type query: dict
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        params = {"briefRepresentation": brief_representation}
        url = urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path)

        if search_text is not None and search_text.strip() != "":
            params["search"] = search_text

        if "first" in query and "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, params)

    async def a_get_realm_role_groups(
        self,
        role_name: str,
        query: dict | None = None,
        brief_representation: bool = True,
    ) -> list:
        """
        Get role groups of realm by role name asynchronously.

        :param role_name: Name of the role.
        :type role_name: str
        :param query: Additional Query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_parameters_226)
        :type query: dict
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak Server Response (GroupRepresentation)
        :rtype: list
        """
        query = query or {}
        params = {"briefRepresentation": brief_representation}
        query.update(params)

        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        url = urls_patterns.URL_ADMIN_REALM_ROLES_GROUPS.format(**params_path)

        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    async def a_get_realm_role_members(self, role_name: str, query: dict | None = None) -> list:
        """
        Get role members of realm by role name asynchronously.

        :param role_name: Name of the role.
        :type role_name: str
        :param query: Additional Query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_roles_resource)
        :type query: dict
        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        return await self.a___fetch_all(
            urls_patterns.URL_ADMIN_REALM_ROLES_MEMBERS.format(**params_path),
            query,
        )

    async def a_get_default_realm_role_id(self) -> str:
        """
        Get the ID of the default realm role asynchronously.

        :return: Realm role ID
        :rtype: str
        """
        all_realm_roles = await self.a_get_realm_roles()
        default_realm_roles = [
            realm_role
            for realm_role in all_realm_roles
            if realm_role["name"] == f"default-roles-{self.connection.realm_name}".lower()
        ]
        return default_realm_roles[0]["id"]

    async def a_get_realm_default_roles(self) -> list:
        """
        Get all the default realm roles asyncho asynchronously.

        :return: Keycloak Server Response (UserRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": await self.a_get_default_realm_role_id(),
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES_REALM.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_remove_realm_default_roles(self, payload: dict) -> bytes:
        """
        Remove a set of default realm roles asynchronously.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": await self.a_get_default_realm_role_id(),
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_add_realm_default_roles(self, payload: dict) -> bytes:
        """
        Add a set of default realm roles asynchronously.

        :param payload: List of RoleRepresentations
        :type payload: list
        :return: Keycloak Server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": await self.a_get_default_realm_role_id(),
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLE_COMPOSITES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    async def a_get_client_roles(self, client_id: str, brief_representation: bool = True) -> list:
        """
        Get all roles for the client asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_role(self, client_id: str, role_name: str) -> dict:
        """
        Get client role by name asynchronously.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: Role object
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_role_id(self, client_id: str, role_name: str) -> str:
        """
        Get client role id by name asynchronously.

        This is required for further actions with this role.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :return: role_id
        :rtype: str
        """
        role = await self.a_get_client_role(client_id, role_name)
        return role.get("id")

    async def a_create_client_role(
        self,
        client_role_id: str,
        payload: dict,
        skip_exists: bool = False,
    ) -> str:
        """
        Create a client role asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

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
                res = await self.a_get_client_role(
                    client_id=client_role_id,
                    role_name=payload["name"],
                )
                return res["name"]
            except KeycloakGetError:
                pass

        params_path = {"realm-name": self.connection.realm_name, "id": client_role_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_add_composite_client_roles_to_role(
        self,
        client_role_id: str,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Add composite roles to client role asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_remove_composite_client_roles_from_role(
        self,
        client_role_id: str,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Remove composite roles from a client role asynchronously.

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_update_client_role(self, client_id: str, role_name: str, payload: dict) -> bytes:
        """
        Update a client role asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :param payload: RoleRepresentation
        :type payload: dict
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_client_role(self, client_role_id: str, role_name: str) -> bytes:
        """
        Delete a client role asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :type client_role_id: str
        :param role_name: role's name (not id!)
        :type role_name: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_role_id,
            "role-name": role_name,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_assign_client_role(self, user_id: str, client_id: str, roles: str | list) -> bytes:
        """
        Assign a client role to a user asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_role_members(
        self,
        client_id: str,
        role_name: str,
        **query: dict,
    ) -> list:
        """
        Get members by client role asynchronously.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response (UserRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        return await self.a___fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_MEMBERS.format(**params_path),
            query,
        )

    async def a_get_client_role_groups(
        self,
        client_id: str,
        role_name: str,
        **query: dict,
    ) -> list:
        """
        Get group members by client role asynchronously.

        :param client_id: The client id
        :type client_id: str
        :param role_name: the name of role to be queried.
        :type role_name: str
        :param query: Additional query parameters
            (see https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clients_resource)
        :type query: dict
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "role-name": role_name,
        }
        return await self.a___fetch_all(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_GROUPS.format(**params_path),
            query,
        )

    async def a_get_role_by_id(self, role_id: str) -> dict:
        """
        Get a specific role's representation asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: id of role
        :type role_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_update_role_by_id(self, role_id: str, payload: dict) -> bytes:
        """
        Update the role asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param payload: RoleRepresentation
        :type payload: dict
        :param role_id: id of role
        :type role_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_role_by_id(self, role_id: str) -> bytes:
        """
        Delete a role by its id asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: id of role
        :type role_id: str
        :returns: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_create_realm_role(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a new role for the realm or client asynchronously.

        :param payload: The role (use RoleRepresentation)
        :type payload: dict
        :param skip_exists: If true then do not raise an error if realm role already exists
        :type skip_exists: bool
        :return: Realm role name
        :rtype: str
        """
        if skip_exists:
            try:
                role = await self.a_get_realm_role(role_name=payload["name"])
                return role["name"]
            except KeycloakGetError:
                pass

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_get_realm_role(self, role_name: str) -> dict:
        """
        Get realm role by role name asynchronously.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_name: role's name, not id!
        :type role_name: str
        :return: role
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_realm_role_by_id(self, role_id: str) -> dict:
        """
        Get realm role by role id.

        RoleRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_rolerepresentation

        :param role_id: role's id, not name!
        :type role_id: str
        :return: role
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "role-id": role_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_ID.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_realm_role(self, role_name: str, payload: dict) -> bytes:
        """
        Update a role for the realm by name asynchronously.

        :param role_name: The name of the role to be updated
        :type role_name: str
        :param payload: The role (use RoleRepresentation)
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_realm_role(self, role_name: str) -> bytes:
        """
        Delete a role for the realm by name asynchronously.

        :param role_name: The role name
        :type role_name: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_add_composite_realm_roles_to_role(
        self,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Add composite roles to the role asynchronously.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_remove_composite_realm_roles_to_role(
        self,
        role_name: str,
        roles: str | list,
    ) -> bytes:
        """
        Remove composite roles from the role asynchronously.

        :param role_name: The name of the role
        :type role_name: str
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_composite_realm_roles_of_role(self, role_name: str) -> list:
        """
        Get composite roles of the role asynchronously.

        :param role_name: The name of the role
        :type role_name: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "role-name": role_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_assign_realm_roles_to_client_scope(
        self,
        client_id: str,
        roles: str | list,
    ) -> dict | bytes:
        """
        Assign realm roles to a client's scope asynchronously.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_realm_roles_of_client_scope(
        self,
        client_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete realm roles of a client's scope asynchronously.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_realm_roles_of_client_scope(self, client_id: str) -> list:
        """
        Get all realm roles for a client's scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_REALM_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_assign_client_roles_to_client_scope(
        self,
        client_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> dict | bytes:
        """
        Assign client roles to a client's dedicated scope asynchronously.

        To assign roles to a client scope, use a_add_client_specific_roles_to_client_scope.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_client_roles_of_client_scope(
        self,
        client_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles of a client's dedicated scope asynchronously.

        To remove roles from a client scope, use a_remove_client_specific_roles_of_client_scope.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_roles_of_client_scope(
        self,
        client_id: str,
        client_roles_owner_id: str,
    ) -> list:
        """
        Get all client roles for a client's scope asynchronously.

        To get roles from a client scope, use a_get_client_roles_of_client_scope.

        :param client_id: id of client (not client-id)
        :type client_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "client": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_assign_realm_roles(self, user_id: str, roles: str | list) -> bytes:
        """
        Assign realm roles to a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_realm_roles_of_user(self, user_id: str, roles: str | list) -> bytes:
        """
        Delete realm roles of a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :param roles: roles list or role (use RoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_realm_roles_of_user(self, user_id: str) -> list:
        """
        Get all realm roles for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_available_realm_roles_of_user(self, user_id: str) -> list:
        """
        Get all available (i.e. unassigned) realm roles for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_AVAILABLE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_composite_realm_roles_of_user(
        self,
        user_id: str,
        brief_representation: bool = True,
    ) -> list:
        """
        Get all composite (i.e. implicit) realm roles for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_REALM_ROLES_COMPOSITE.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_assign_group_realm_roles(self, group_id: str, roles: str | list) -> bytes:
        """
        Assign realm roles to a group asynchronously.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_group_realm_roles(self, group_id: str, roles: str | list) -> bytes:
        """
        Delete realm roles of a group asynchronously.

        :param group_id: id of group
        :type group_id: str
        :param roles: roles list or role (use GroupRoleRepresentation)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_group_realm_roles(
        self,
        group_id: str,
        brief_representation: bool = True,
    ) -> list:
        """
        Get all realm roles for a group asynchronously.

        :param group_id: id of the group
        :type group_id: str
        :param brief_representation: whether to omit role attributes in the response
        :type brief_representation: bool
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": group_id}
        params = {"briefRepresentation": brief_representation}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_assign_group_client_roles(
        self,
        group_id: str,
        client_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Assign client roles to a group asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_group_client_roles(self, group_id: str, client_id: str) -> list:
        """
        Get client roles of a group asynchronously.

        :param group_id: id of group
        :type group_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_group_client_roles(
        self,
        group_id: str,
        client_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles of a group asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_all_roles_of_user(self, user_id: str) -> list:
        """
        Get all level roles for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_ALL_ROLES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_roles_of_user(self, user_id: str, client_id: str) -> list:
        """
        Get all client roles for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return await self.a__get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES,
            user_id,
            client_id,
        )

    async def a_get_available_client_roles_of_user(self, user_id: str, client_id: str) -> list:
        """
        Get available client role-mappings for a user asynchronously.

        :param user_id: id of user
        :type user_id: str
        :param client_id: id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        return await self.a__get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE,
            user_id,
            client_id,
        )

    async def a_get_composite_client_roles_of_user(
        self,
        user_id: str,
        client_id: str,
        brief_representation: bool = False,
    ) -> list:
        """
        Get composite client role-mappings for a user asynchronously.

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
        return await self.a__get_client_roles_of_user(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE,
            user_id,
            client_id,
            **params,
        )

    async def a__get_client_roles_of_user(
        self,
        client_level_role_mapping_url: str,
        user_id: str,
        client_id: str,
        **params: dict,
    ) -> list:
        """
        Get client roles of a single user helper asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_get(
            client_level_role_mapping_url.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_client_roles_of_user(
        self,
        user_id: str,
        client_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles from a user asynchronously.

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
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_authentication_flows(self) -> list:
        """
        Get authentication flows asynchronously.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_FLOWS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_authentication_flow_for_id(self, flow_id: str) -> dict:
        """
        Get one authentication flow by it's id asynchronously.

        Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: the id of a flow NOT it's alias
        :type flow_id: str
        :return: Keycloak server response (AuthenticationFlowRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-id": flow_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_FLOWS_ALIAS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_authentication_flow(
        self,
        payload: dict,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create a new authentication flow asynchronously.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_FLOWS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_copy_authentication_flow(self, payload: dict, flow_alias: str) -> bytes:
        """
        Copy existing authentication flow under a new name asynchronously.

        The new name is given as 'newName' attribute of the passed payload.

        :param payload: JSON containing 'newName' attribute
        :type payload: dict
        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_FLOWS_COPY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_delete_authentication_flow(self, flow_id: str) -> bytes:
        """
        Delete authentication flow asynchronously.

        AuthenticationInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationinforepresentation

        :param flow_id: authentication flow id
        :type flow_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": flow_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_FLOW.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_authentication_flow_executions(self, flow_alias: str) -> list:
        """
        Get authentication flow executions asynchronously.

        Returns all execution steps

        :param flow_alias: the flow alias
        :type flow_alias: str
        :return: Response(json)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_authentication_flow_executions(
        self,
        payload: dict,
        flow_alias: str,
    ) -> bytes:
        """
        Update an authentication flow execution asynchronously.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_ACCEPTED, HTTP_NO_CONTENT],
        )

    async def a_get_authentication_flow_execution(self, execution_id: str) -> dict:
        """
        Get authentication flow execution asynchronously.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: the execution ID
        :type execution_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": execution_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_authentication_flow_execution(
        self,
        payload: dict,
        flow_alias: str,
    ) -> bytes:
        """
        Create an authentication flow execution asynchronously.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_EXECUTION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_delete_authentication_flow_execution(self, execution_id: str) -> bytes:
        """
        Delete authentication flow execution asynchronously.

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationexecutioninforepresentation

        :param execution_id: keycloak client id (not oauth client-id)
        :type execution_id: str
        :return: Keycloak server response (json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": execution_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_create_authentication_flow_subflow(
        self,
        payload: dict,
        flow_alias: str,
        skip_exists: bool = False,
    ) -> bytes:
        """
        Create a new sub authentication flow for a given authentication flow asynchronously.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :param flow_alias: The flow alias
        :type flow_alias: str
        :param skip_exists: Do not raise an error if authentication flow already exists
        :type skip_exists: bool
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "flow-alias": flow_alias}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_FLOW.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )

    async def a_get_authenticator_providers(self) -> list:
        """
        Get authenticator providers list asynchronously.

        :return: Authenticator providers
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_PROVIDERS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_authenticator_provider_config_description(self, provider_id: str) -> dict:
        """
        Get authenticator's provider configuration description asynchronously.

        AuthenticatorConfigInfoRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfiginforepresentation

        :param provider_id: Provider Id
        :type provider_id: str
        :return: AuthenticatorConfigInfoRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "provider-id": provider_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG_DESCRIPTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_authenticator_config(self, config_id: str) -> dict:
        """
        Get authenticator configuration asynchronously.

        Returns all configuration details.

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_authenticator_config(self, payload: dict, config_id: str) -> bytes:
        """
        Update an authenticator configuration asynchronously.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfigrepresentation

        :param payload: AuthenticatorConfigRepresentation
        :type payload: dict
        :param config_id: Authenticator config id
        :type config_id: str
        :return: Response(json)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_authenticator_config(self, config_id: str) -> bytes:
        """
        Delete a authenticator configuration asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authentication_management_resource

        :param config_id: Authenticator config id
        :type config_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": config_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_AUTHENTICATOR_CONFIG.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_sync_users(self, storage_id: str, action: str) -> bytes:
        """
        Trigger user sync from provider asynchronously.

        :param storage_id: The id of the user storage provider
        :type storage_id: str
        :param action: Action can be "triggerFullSync" or "triggerChangedUsersSync"
        :type action: str
        :return: Keycloak server response
        :rtype: bytes
        """
        data = {"action": action}
        params_query = {"action": action}

        params_path = {"realm-name": self.connection.realm_name, "id": storage_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_USER_STORAGE.format(**params_path),
            data=json.dumps(data),
            **params_query,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    async def a_get_client_scopes(self) -> list:
        """
        Get client scopes asynchronously.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

        :return: Keycloak server response Array of (ClientScopeRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_scope(self, client_scope_id: str) -> dict:
        """
        Get client scope asynchronously.

        Get representation of the client scopes for the realm where we are connected to
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_scope_by_name(self, client_scope_name: str) -> dict | None:
        """
        Get client scope by name asynchronously.

        Get representation of the client scope identified by the client scope name.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes
        :param client_scope_name: (str) Name of the client scope
        :type client_scope_name: str
        :returns: ClientScopeRepresentation or None
        :rtype: dict
        """
        client_scopes = await self.a_get_client_scopes()
        for client_scope in client_scopes:
            if client_scope["name"] == client_scope_name:
                return client_scope

        return None

    async def a_create_client_scope(self, payload: dict, skip_exists: bool = False) -> str:
        """
        Create a client scope asynchronously.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientscopes

        :param payload: ClientScopeRepresentation
        :type payload: dict
        :param skip_exists: If true then do not raise an error if client scope already exists
        :type skip_exists: bool
        :return: Client scope id
        :rtype: str
        """
        if skip_exists:
            exists = await self.a_get_client_scope_by_name(client_scope_name=payload["name"])

            if exists is not None:
                return exists["id"]

        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
            skip_exists=skip_exists,
        )
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_update_client_scope(self, client_scope_id: str, payload: dict) -> bytes:
        """
        Update a client scope asynchronously.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ClientScopeRepresentation
        :type payload: dict
        :return: Keycloak server response (ClientScopeRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_client_scope(self, client_scope_id: str) -> bytes:
        """
        Delete existing client scope asynchronously.

        ClientScopeRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_client_scopes_resource

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_mappers_from_client_scope(self, client_scope_id: str) -> list:
        """
        Get a list of all mappers connected to the client scope asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource
        :param client_scope_id: Client scope id
        :type client_scope_id: str
        :returns: Keycloak server response (ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_add_mapper_to_client_scope(self, client_scope_id: str, payload: dict) -> bytes:
        """
        Add a mapper to a client scope asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_create_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_delete_mapper_from_client_scope(
        self,
        client_scope_id: str,
        protocol_mapper_id: str,
    ) -> bytes:
        """
        Delete a mapper from a client scope asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_delete_mapper

        :param client_scope_id: The id of the client scope
        :type client_scope_id: str
        :param protocol_mapper_id: Protocol mapper id
        :type protocol_mapper_id: str
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_update_mapper_in_client_scope(
        self,
        client_scope_id: str,
        protocol_mapper_id: str,
        payload: dict,
    ) -> bytes:
        """
        Update an existing protocol mapper in a client scope asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource

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
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "protocol-mapper-id": protocol_mapper_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_default_default_client_scopes(self) -> list:
        """
        Get default default client scopes asynchronously.

        Return list of default default client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_default_default_client_scope(self, scope_id: str) -> bytes:
        """
        Delete default default client scope asynchronously.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_add_default_default_client_scope(self, scope_id: str) -> bytes:
        """
        Add default default client scope asynchronously.

        :param scope_id: default default client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        payload = {"realm": self.connection.realm_name, "clientScopeId": scope_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_default_optional_client_scopes(self) -> list:
        """
        Get default optional client scopes asynchronously.

        Return list of default optional client scopes

        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_delete_default_optional_client_scope(self, scope_id: str) -> bytes:
        """
        Delete default optional client scope asynchronously.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_add_default_optional_client_scope(self, scope_id: str) -> bytes:
        """
        Add default optional client scope asynchronously.

        :param scope_id: default optional client scope id
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": scope_id}
        payload = {"realm": self.connection.realm_name, "clientScopeId": scope_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_add_client_specific_roles_to_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Assign client roles to a client scope asynchronously.

        To assign roles to a client's dedicated scope, use
        a_assign_client_roles_to_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation, must include id and name)
        :type roles: list
        :return: Keycloak server response
        :rtype: dict
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_remove_client_specific_roles_of_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
        roles: str | list,
    ) -> bytes:
        """
        Delete client roles of a client scope asynchronously.

        To delete roles from a client's dedicated scope,
        use a_delete_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :param roles: roles list or role (use RoleRepresentation, must include id and name)
        :type roles: list
        :return: Keycloak server response
        :rtype: bytes
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_specific_roles_of_client_scope(
        self,
        client_scope_id: str,
        client_roles_owner_id: str,
    ) -> list:
        """
        Get all client roles for a client scope asynchronously.

        To get roles for a client's dedicated scope,
        use a_get_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :param client_roles_owner_id: id of client (not client-id) who has the roles
        :type client_roles_owner_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "scope-id": client_scope_id,
            "client-id": client_roles_owner_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_all_roles_of_client_scope(self, client_scope_id: str) -> list:
        """
        Get all client roles for a client scope.

        To get roles for a client's dedicated scope,
        use a_get_client_roles_of_client_scope.

        :param client_scope_id: client scope id
        :type client_scope_id: str
        :return: Keycloak server response (array RoleRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "scope-id": client_scope_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SCOPE_ROLE_MAPPINGS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_mappers_from_client(self, client_id: str) -> list:
        """
        List of all client mappers asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocolmapperrepresentation

        :param client_id: Client id
        :type client_id: str
        :returns: KeycloakServerResponse (list of ProtocolMapperRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path),
        )

        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_OK])

    async def a_add_mapper_to_client(self, client_id: str, payload: dict) -> bytes:
        """
        Add a mapper to a client asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_create_mapper

        :param client_id: The id of the client
        :type client_id: str
        :param payload: ProtocolMapperRepresentation
        :type payload: dict
        :return: Keycloak server Response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPERS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_update_client_mapper(self, client_id: str, mapper_id: str, payload: dict) -> bytes:
        """
        Update client mapper asynchronously.

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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "protocol-mapper-id": mapper_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_remove_client_mapper(self, client_id: str, client_mapper_id: str) -> bytes:
        """
        Remove a mapper from the client asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_protocol_mappers_resource

        :param client_id: The id of the client
        :type client_id: str
        :param client_mapper_id: The id of the mapper to be deleted
        :type client_mapper_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "protocol-mapper-id": client_mapper_id,
        }
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_generate_client_secrets(self, client_id: str) -> bytes:
        """
        Generate a new secret for the client asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_regeneratesecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path),
            data=None,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    async def a_get_client_secrets(self, client_id: str) -> dict:
        """
        Get representation of the client secrets asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientsecret

        :param client_id:  id of client (not client-id)
        :type client_id: str
        :return: Keycloak server response (ClientRepresentation)
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_components(self, query: dict | None = None) -> list:
        """
        Get components asynchronously.

        Return a list of components, filtered according to query parameters

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param query: Query parameters (optional)
        :type query: dict
        :return: components list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_component(self, payload: dict) -> str:
        """
        Create a new component asynchronously.

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param payload: ComponentRepresentation
        :type payload: dict
        :return: Component id
        :rtype: str
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
            data=json.dumps(payload),
        )
        raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[HTTP_CREATED])
        _last_slash_idx = data_raw.headers["Location"].rindex("/")
        return data_raw.headers["Location"][_last_slash_idx + 1 :]

    async def a_get_component(self, component_id: str) -> dict | bytes:
        """
        Get representation of the component asynchronously.

        :param component_id: Component id

        ComponentRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation

        :param component_id: Id of the component
        :type component_id: str
        :return: ComponentRepresentation
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_component(self, component_id: str, payload: dict) -> bytes:
        """
        Update the component asynchronously.

        :param component_id: Component id
        :type component_id: str
        :param payload: ComponentRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_componentrepresentation
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_delete_component(self, component_id: str) -> bytes:
        """
        Delete the component asynchronously.

        :param component_id: Component id
        :type component_id: str
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "component-id": component_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakDeleteError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_keys(self) -> list:
        """
        Get keys asynchronously.

        Return a list of keys, filtered according to query parameters

        KeysMetadataRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_key_resource

        :return: keys list
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_KEYS.format(**params_path),
            data=None,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_admin_events(self, query: dict | None = None) -> list:
        """
        Get Administrative events asynchronously.

        Return a list of events, filtered according to query parameters

        AdminEvents Representation array
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getevents
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_get_adminrealmsrealmadmin_events

        :param query: Additional query parameters
        :type query: dict
        :return: events list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_ADMIN_EVENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_events(self, query: dict | None = None) -> list:
        """
        Get events asynchronously.

        Return a list of events, filtered according to query parameters

        EventRepresentation array
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_eventrepresentation

        :param query: Additional query parameters
        :type query: dict
        :return: events list
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_USER_EVENTS.format(**params_path),
            data=None,
            **query,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_set_events(self, payload: dict) -> bytes:
        """
        Set realm events configuration asynchronously.

        RealmEventsConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmeventsconfigrepresentation

        :param payload: Payload object for the events configuration
        :type payload: dict
        :return: Http response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_EVENTS_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_get_client_all_sessions(self, client_id: str, query: dict | None = None) -> list:
        """
        Get sessions associated with the client asynchronously.

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_usersessionrepresentation

        :param client_id: id of client
        :type client_id: str
        :param query: Additional query parameters
        :type query: dict
        :return: UserSessionRepresentation
        :rtype: list
        """
        query = query or {}
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_ALL_SESSIONS.format(**params_path)
        if "first" in query or "max" in query:
            return await self.a___fetch_paginated(url, query)

        return await self.a___fetch_all(url, query)

    async def a_get_client_sessions_stats(self) -> dict:
        """
        Get current session count for all clients with active sessions asynchronously.

        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_getclientsessionstats

        :return: Dict of clients and session count
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_SESSION_STATS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_management_permissions(self, client_id: str) -> list:
        """
        Get management permissions for a client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_client_management_permissions(self, payload: dict, client_id: str) -> bytes:
        """
        Update management permissions for a client asynchronously.

        ManagementPermissionReference
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_managementpermissionreference

        Payload example::

            payload={
                "enabled": true
            }

        :param payload: ManagementPermissionReference
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_OK])

    async def a_get_client_authz_policy_scopes(self, client_id: str, policy_id: str) -> list:
        """
        Get scopes for a given policy asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_SCOPES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_authz_policy_resources(self, client_id: str, policy_id: str) -> list:
        """
        Get resources for a given policy asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: No Document
        :type policy_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_POLICY_RESOURCES.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_client_authz_scope_permission(self, client_id: str, scope_id: str) -> list:
        """
        Get permissions for a given scope asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "scope-id": scope_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_create_client_authz_scope_permission(self, payload: dict, client_id: str) -> bytes:
        """
        Create permissions for a authz scope asynchronously.

        Payload example::

            payload={
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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_ADD_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
            max=-1,
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_update_client_authz_scope_permission(
        self,
        payload: dict,
        client_id: str,
        scope_id: str,
    ) -> bytes:
        """
        Update permissions for a given scope asynchronously.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param scope_id: No Document
        :type scope_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "scope-id": scope_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_CREATED])

    async def a_update_client_authz_resource_permission(
        self,
        payload: dict,
        client_id: str,
        resource_id: str,
    ) -> bytes:
        """
        Update permissions for a given resource asynchronously.

        Payload example::

            payload={
                "id": resource_id,
                "name": "My Permission Name",
                "type": "resource",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "resources": [some_resource_id],
                "scopes": [],
                "policies": [some_policy_id],
            }

        :param payload: No Document
        :type payload: dict
        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param resource_id: No Document
        :type resource_id: str
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "resource-id": resource_id,
        }
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[HTTP_CREATED])

    async def a_get_client_authz_client_policies(self, client_id: str) -> list:
        """
        Get policies for a given client asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_get_client_authz_permission_associated_policies(
        self,
        client_id: str,
        policy_id: str,
    ) -> list:
        """
        Get associated policies for a given client permission asynchronously.

        :param client_id: id in ClientRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :param policy_id: id in PolicyRepresentation
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_policyrepresentation
        :type policy_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_POLICIES.format(
                **params_path,
            ),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[HTTP_OK])

    async def a_create_client_authz_client_policy(self, payload: dict, client_id: str) -> bytes:
        """
        Create a new policy for a given client asynchronously.

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
            https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_clientrepresentation
        :type client_id: str
        :return: Keycloak server response (RoleRepresentation)
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_get_composite_client_roles_of_group(
        self,
        client_id: str,
        group_id: str,
        brief_representation: bool = True,
    ) -> list:
        """
        Get the composite client roles of the given group for the given client asynchronously.

        :param client_id: id of the client.
        :type client_id: str
        :param group_id: id of the group.
        :type group_id: str
        :param brief_representation: whether to omit attributes in the response
        :type brief_representation: bool
        :return: the composite client roles of the group (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": group_id,
            "client-id": client_id,
        }
        params = {"briefRepresentation": brief_representation}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES_COMPOSITE.format(**params_path),
            **params,
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_get_role_client_level_children(self, client_id: str, role_id: str) -> list:
        """
        Get the child roles async of which the given composite client role is composed of.

        :param client_id: id of the client.
        :type client_id: str
        :param role_id: id of the role.
        :type role_id: str
        :return: the child roles (list of RoleRepresentation).
        :rtype: list
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "role-id": role_id,
            "client-id": client_id,
        }
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_CLIENT_ROLE_CHILDREN.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_upload_certificate(self, client_id: str, certcont: str) -> dict:
        """
        Upload a new certificate for the client asynchronously.

        :param client_id: id of the client.
        :type client_id: str
        :param certcont: the content of the certificate.
        :type certcont: str
        :return: dictionary {"certificate": "<certcont>"},
                 where <certcont> is the content of the uploaded certificate.
        :rtype: dict
        """
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "attr": "jwt.credential",
        }
        m = MultipartEncoder(fields={"keystoreFormat": "Certificate PEM", "file": certcont})
        new_headers = copy.deepcopy(self.connection.headers)
        new_headers["Content-Type"] = m.content_type
        self.connection.headers = new_headers
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLIENT_CERT_UPLOAD.format(**params_path),
            data=m,
            headers=new_headers,
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    async def a_get_required_action_by_alias(self, action_alias: str) -> dict:
        """
        Get a required action by its alias asynchronously.

        :param action_alias: the alias of the required action.
        :type action_alias: str
        :return: the required action (RequiredActionProviderRepresentation).
        :rtype: dict
        """
        actions = await self.a_get_required_actions()
        for a in actions:
            if a["alias"] == action_alias:
                return a
        return None

    async def a_get_required_actions(self) -> list:
        """
        Get the required actions for the realms asynchronously.

        :return: the required actions (list of RequiredActionProviderRepresentation).
        :rtype: list
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_update_required_action(self, action_alias: str, payload: dict) -> bytes:
        """
        Update a required action asynchronously.

        :param action_alias: the action alias.
        :type action_alias: str
        :param payload: the new required action (RequiredActionProviderRepresentation).
        :type payload: dict
        :return: empty dictionary.
        :rtype: bytes
        """
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        params_path = {"realm-name": self.connection.realm_name, "action-alias": action_alias}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_REQUIRED_ACTIONS_ALIAS.format(**params_path),
            data=payload,
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    async def a_get_bruteforce_detection_status(self, user_id: str) -> dict:
        """
        Get bruteforce detection status for user asynchronously.

        :param user_id: User id
        :type user_id: str
        :return: Bruteforce status.
        :rtype: dict
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_get(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    async def a_clear_bruteforce_attempts_for_user(self, user_id: str) -> bytes:
        """
        Clear bruteforce attempts for user asynchronously.

        :param user_id: User id
        :type user_id: str
        :return: empty dictionary.
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name, "id": user_id}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION_USER.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_clear_all_bruteforce_attempts(self) -> bytes:
        """
        Clear bruteforce attempts for all users in realm asynchronously.

        :return: empty dictionary.
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_delete(
            urls_patterns.URL_ADMIN_ATTACK_DETECTION.format(**params_path),
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    async def a_clear_keys_cache(self) -> bytes:
        """
        Clear keys cache asynchronously.

        :return: empty dictionary.
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLEAR_KEYS_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_clear_realm_cache(self) -> bytes:
        """
        Clear realm cache asynchronously.

        :return: empty dictionary.
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLEAR_REALM_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_clear_user_cache(self) -> bytes:
        """
        Clear user cache asynchronously.

        :return: empty dictionary.
        :rtype: bytes
        """
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_CLEAR_USER_CACHE.format(**params_path),
            data="",
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_NO_CONTENT],
        )

    async def a_change_execution_priority(self, execution_id: str, diff: int) -> None:
        """
        Raise or lower execution priority of diff time.

        :param execution_id: The ID of the execution
        :type execution_id: str
        :param diff: The difference in priority, positive to raise, negative to lower, the value
            is the number of times
        :type diff: int
        :raises KeycloakPostError: when post requests are failed
        """
        params_path = {"id": execution_id, "realm-name": self.connection.realm_name}
        if diff > 0:
            for _ in range(diff):
                data_raw = await self.connection.a_raw_post(
                    urls_patterns.URL_AUTHENTICATION_EXECUTION_RAISE_PRIORITY.format(
                        **params_path,
                    ),
                    data="{}",
                )
                raise_error_from_response(
                    data_raw,
                    KeycloakPostError,
                    expected_codes=[HTTP_NO_CONTENT],
                )
        elif diff < 0:
            for _ in range(-diff):
                data_raw = await self.connection.a_raw_post(
                    urls_patterns.URL_AUTHENTICATION_EXECUTION_LOWER_PRIORITY.format(
                        **params_path,
                    ),
                    data="{}",
                )
                raise_error_from_response(
                    data_raw,
                    KeycloakPostError,
                    expected_codes=[HTTP_NO_CONTENT],
                )

    async def a_create_execution_config(self, execution_id: str, payload: dict) -> bytes:
        """
        Update execution with new configuration.

        AuthenticatorConfigRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticatorconfigrepresentation

        :param execution_id: The ID of the execution
        :type execution_id: str
        :param payload: Configuration to add to the execution
        :type payload: dir
        :return: Response(json)
        :rtype: dict
        """
        params_path = {"id": execution_id, "realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_post(
            urls_patterns.URL_ADMIN_FLOWS_EXECUTION_CONFIG.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[HTTP_CREATED],
        )

    async def a_update_authentication_flow(self, flow_id: str, payload: dict) -> bytes:
        """
        Update an authentication flow.

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: The id of the flow
        :type flow_id: str
        :param payload: AuthenticationFlowRepresentation
        :type payload: dict
        :return: Keycloak server response
        :rtype: bytes
        """
        params_path = {"id": flow_id, "realm-name": self.connection.realm_name}
        data_raw = await self.connection.a_raw_put(
            urls_patterns.URL_ADMIN_FLOW.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[HTTP_ACCEPTED, HTTP_NO_CONTENT],
        )
