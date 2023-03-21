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

"""Keycloak UMA module.

The module contains a UMA compatible client for keycloak:
https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html
"""
import json
from typing import Iterable
from urllib.parse import quote_plus

from .connection import ConnectionManager
from .exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    raise_error_from_response,
)
from .openid_connection import KeycloakOpenIDConnection
from .uma_permissions import UMAPermission
from .urls_patterns import URL_UMA_WELL_KNOWN


class KeycloakUMA:
    """Keycloak UMA client.

    :param connection: OpenID connection manager
    """

    def __init__(self, connection: KeycloakOpenIDConnection):
        """Init method.

        :param connection: OpenID connection manager
        :type connection: KeycloakOpenIDConnection
        """
        self.connection = connection
        custom_headers = self.connection.custom_headers or {}
        custom_headers.update({"Content-Type": "application/json"})
        self.connection.custom_headers = custom_headers
        self._well_known = None

    def _fetch_well_known(self):
        params_path = {"realm-name": self.connection.realm_name}
        data_raw = self.connection.raw_get(URL_UMA_WELL_KNOWN.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    @staticmethod
    def format_url(url, **kwargs):
        """Substitute url path parameters.

        Given a parameterized url string, returns the string after url encoding and substituting
        the given params. For example,
        `format_url("https://myserver/{my_resource}/{id}", my_resource="hello world", id="myid")`
        would produce `https://myserver/hello+world/myid`.

        :param url: url string to format
        :type url: str
        :param kwargs: dict containing kwargs to substitute
        :type kwargs: dict
        :return: formatted string
        :rtype: str
        """
        return url.format(**{k: quote_plus(v) for k, v in kwargs.items()})

    @property
    def uma_well_known(self):
        """Get the well_known UMA2 config.

        :returns: It lists endpoints and other configuration options relevant
        :rtype: dict
        """
        # per instance cache
        if not self._well_known:
            self._well_known = self._fetch_well_known()
        return self._well_known

    def resource_set_create(self, payload):
        """Create a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#rfc.section.2.2.1

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param payload: ResourceRepresentation
        :type payload: dict
        :return: ResourceRepresentation with the _id property assigned
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            self.uma_well_known["resource_registration_endpoint"], data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def resource_set_update(self, resource_id, payload):
        """Update a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#update-resource-set

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param resource_id: id of the resource
        :type resource_id: str
        :param payload: ResourceRepresentation
        :type payload: dict
        :return: Response dict (empty)
        :rtype: dict
        """
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_put(url, data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def resource_set_read(self, resource_id):
        """Read a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#read-resource-set

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param resource_id: id of the resource
        :type resource_id: str
        :return: ResourceRepresentation
        :rtype: dict
        """
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_get(url)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def resource_set_delete(self, resource_id):
        """Delete a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#delete-resource-set

        :param resource_id: id of the resource
        :type resource_id: str
        :return: Response dict (empty)
        :rtype: dict
        """
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_delete(url)
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def resource_set_list_ids(
        self,
        name: str = "",
        exact_name: bool = False,
        uri: str = "",
        owner: str = "",
        resource_type: str = "",
        scope: str = "",
        first: int = 0,
        maximum: int = -1,
    ):
        """Query for list of resource set ids.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        :param name: query resource name
        :type name: str
        :param exact_name: query exact match for resource name
        :type exact_name: bool
        :param uri: query resource uri
        :type uri: str
        :param owner: query resource owner
        :type owner: str
        :param resource_type: query resource type
        :type resource_type: str
        :param scope: query resource scope
        :type scope: str
        :param first: index of first matching resource to return
        :type first: int
        :param maximum: maximum number of resources to return (-1 for all)
        :type maximum: int
        :return: List of ids
        :rtype: List[str]
        """
        query = dict()
        if name:
            query["name"] = name
            if exact_name:
                query["exactName"] = "true"
        if uri:
            query["uri"] = uri
        if owner:
            query["owner"] = owner
        if resource_type:
            query["type"] = resource_type
        if scope:
            query["scope"] = scope
        if first > 0:
            query["first"] = first
        if maximum >= 0:
            query["max"] = maximum

        data_raw = self.connection.raw_get(
            self.uma_well_known["resource_registration_endpoint"], **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def resource_set_list(self):
        """List all resource sets.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :yields: Iterator over a list of ResourceRepresentations
        :rtype: Iterator[dict]
        """
        for resource_id in self.resource_set_list_ids():
            resource = self.resource_set_read(resource_id)
            yield resource

    def permission_ticket_create(self, permissions: Iterable[UMAPermission]):
        """Create a permission ticket.

        :param permissions: Iterable of uma permissions to validate the token against
        :type permissions: Iterable[UMAPermission]
        :returns: Keycloak decision
        :rtype: boolean
        :raises KeycloakPostError: In case permission resource not found
        """
        resources = dict()
        for permission in permissions:
            resource_id = getattr(permission, "resource_id", None)

            if resource_id is None:
                resource_ids = self.resource_set_list_ids(
                    exact_name=True, name=permission.resource, first=0, maximum=1
                )

                if not resource_ids:
                    raise KeycloakPostError("Invalid resource specified")

                setattr(permission, "resource_id", resource_ids[0])

            resources.setdefault(resource_id, set())
            if permission.scope:
                resources[resource_id].add(permission.scope)

        payload = [
            {"resource_id": resource_id, "resource_scopes": list(scopes)}
            for resource_id, scopes in resources.items()
        ]

        data_raw = self.connection.raw_post(
            self.uma_well_known["permission_endpoint"], data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def permissions_check(self, token, permissions: Iterable[UMAPermission]):
        """Check UMA permissions by user token with requested permissions.

        The token endpoint is used to check UMA permissions from Keycloak. It can only be
        invoked by confidential clients.

        https://www.keycloak.org/docs/latest/authorization_services/#_service_authorization_api

        :param token: user token
        :type token: str
        :param permissions: Iterable of uma permissions to validate the token against
        :type permissions: Iterable[UMAPermission]
        :returns: Keycloak decision
        :rtype: boolean
        """
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": ",".join(str(permission) for permission in permissions),
            "response_mode": "decision",
            "audience": self.connection.client_id,
        }

        # Everyone always has the null set of permissions
        # However keycloak cannot evaluate the null set
        if len(payload["permission"]) == 0:
            return True

        connection = ConnectionManager(self.connection.base_url)
        connection.add_param_headers("Authorization", "Bearer " + token)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data_raw = connection.raw_post(self.uma_well_known["token_endpoint"], data=payload)
        try:
            data = raise_error_from_response(data_raw, KeycloakPostError)
        except KeycloakPostError:
            return False
        return data.get("result", False)

    def policy_resource_create(self, resource_id, payload):
        """Create permission policy for resource.

        Supports name, description, scopes, roles, groups, clients

        https://www.keycloak.org/docs/latest/authorization_services/#associating-a-permission-with-a-resource

        :param resource_id: _id of resource
        :type resource_id: str
        :param payload: permission configuration
        :type payload: dict
        :return: PermissionRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_post(
            self.uma_well_known["policy_endpoint"] + f"/{resource_id}", data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError)

    def policy_update(self, policy_id, payload):
        """Update permission policy.

        https://www.keycloak.org/docs/latest/authorization_services/#associating-a-permission-with-a-resource
        https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html#_policyrepresentation

        :param policy_id: id of policy permission
        :type policy_id: str
        :param payload: policy permission configuration
        :type payload: dict
        :return: PermissionRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_put(
            self.uma_well_known["policy_endpoint"] + f"/{policy_id}", data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPutError)

    def policy_delete(self, policy_id):
        """Delete permission policy.

        https://www.keycloak.org/docs/latest/authorization_services/#removing-a-permission
        https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html#_policyrepresentation

        :param policy_id: id of permission policy
        :type policy_id: str
        :return: PermissionRepresentation
        :rtype: dict
        """
        data_raw = self.connection.raw_delete(
            self.uma_well_known["policy_endpoint"] + f"/{policy_id}"
        )
        return raise_error_from_response(data_raw, KeycloakDeleteError)

    def policy_query(
        self,
        resource: str = "",
        name: str = "",
        scope: str = "",
        first: int = 0,
        maximum: int = -1,
    ):
        """Query permission policies.

        https://www.keycloak.org/docs/latest/authorization_services/#querying-permission

        :param resource: query resource id
        :type resource: str
        :param name: query resource name
        :type name: str
        :param scope: query resource scope
        :type scope: str
        :param first: index of first matching resource to return
        :type first: int
        :param maximum: maximum number of resources to return (-1 for all)
        :type maximum: int
        :return: List of ids
        :return: List of ids
        :rtype: List[str]
        """
        query = dict()
        if name:
            query["name"] = name
        if resource:
            query["resource"] = resource
        if scope:
            query["scope"] = scope
        if first > 0:
            query["first"] = first
        if maximum >= 0:
            query["max"] = maximum

        data_raw = self.connection.raw_get(self.uma_well_known["policy_endpoint"], **query)
        return raise_error_from_response(data_raw, KeycloakGetError)
