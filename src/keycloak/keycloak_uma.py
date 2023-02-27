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
from urllib.parse import quote_plus

from .exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    raise_error_from_response,
)
from .keycloak_openid import KeycloakOpenIDConnectionManager
from .urls_patterns import URL_UMA_WELL_KNOWN


class KeycloakUMA:
    """Keycloak UMA client.

    :param connection: OpenID connection manager
    """

    def __init__(self, connection: KeycloakOpenIDConnectionManager):
        """Init method.

        :param connection: OpenID connection manager
        :type connection: KeycloakOpenIDConnectionManager
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

    def resource_set_list_ids(self):
        """List all resource set ids.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        :return: List of ids
        :rtype: List[str]
        """
        data_raw = self.connection.raw_get(self.uma_well_known["resource_registration_endpoint"])
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
