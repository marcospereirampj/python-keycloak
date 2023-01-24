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

from .connection import ConnectionManager
from .exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    raise_error_from_response,
)
from .urls_patterns import URL_UMA_WELL_KNOWN


class KeycloakUMA:
    """Keycloak UMA client.

    :param server_url: Keycloak server url
    :param client_id: client id
    :param realm_name: realm name
    :param client_secret_key: client secret key
    :param verify: True if want check connection SSL
    :param custom_headers: dict of custom header to pass to each HTML request
    :param proxies: dict of proxies to sent the request by.
    :param timeout: connection timeout in seconds
    """

    def __init__(
        self, server_url, realm_name, verify=True, custom_headers=None, proxies=None, timeout=60
    ):
        """Init method.

        :param server_url: Keycloak server url
        :type server_url: str
        :param realm_name: realm name
        :type realm_name: str
        :param verify: True if want check connection SSL
        :type verify: bool
        :param custom_headers: dict of custom header to pass to each HTML request
        :type custom_headers: dict
        :param proxies: dict of proxies to sent the request by.
        :type proxies: dict
        :param timeout: connection timeout in seconds
        :type timeout: int
        """
        self.realm_name = realm_name
        headers = custom_headers if custom_headers is not None else dict()
        headers.update({"Content-Type": "application/json"})
        self.connection = ConnectionManager(
            base_url=server_url, headers=headers, timeout=timeout, verify=verify, proxies=proxies
        )
        self._well_known = None

    def _fetch_well_known(self):
        params_path = {"realm-name": self.realm_name}
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

    def _add_bearer_token_header(self, token):
        self.connection.add_param_headers("Authorization", "Bearer " + token)

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

    def resource_set_create(self, token, payload):
        """Create a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#rfc.section.2.2.1

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param token: client access token
        :type token: str
        :param payload: ResourceRepresentation
        :type payload: dict
        :return: ResourceRepresentation with the _id property assigned
        :rtype: dict
        """
        self._add_bearer_token_header(token)
        data_raw = self.connection.raw_post(
            self.uma_well_known["resource_registration_endpoint"], data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakPostError, expected_codes=[201])

    def resource_set_update(self, token, resource_id, payload):
        """Update a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#update-resource-set

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param token: client access token
        :type token: str
        :param resource_id: id of the resource
        :type resource_id: str
        :param payload: ResourceRepresentation
        :type payload: dict
        :return: Response dict (empty)
        :rtype: dict
        """
        self._add_bearer_token_header(token)
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_put(url, data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def resource_set_read(self, token, resource_id):
        """Read a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#read-resource-set

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param token: client access token
        :type token: str
        :param resource_id: id of the resource
        :type resource_id: str
        :return: ResourceRepresentation
        :rtype: dict
        """
        self._add_bearer_token_header(token)
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_get(url)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def resource_set_delete(self, token, resource_id):
        """Delete a resource set.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#delete-resource-set

        :param token: client access token
        :type token: str
        :param resource_id: id of the resource
        :type resource_id: str
        :return: Response dict (empty)
        :rtype: dict
        """
        self._add_bearer_token_header(token)
        url = self.format_url(
            self.uma_well_known["resource_registration_endpoint"] + "/{id}", id=resource_id
        )
        data_raw = self.connection.raw_delete(url)
        return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])

    def resource_set_list_ids(self, token):
        """List all resource set ids.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        :param token: client access token
        :type token: str
        :return: List of ids
        :rtype: List[str]
        """
        self._add_bearer_token_header(token)
        data_raw = self.connection.raw_get(self.uma_well_known["resource_registration_endpoint"])
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def resource_set_list(self, token):
        """List all resource sets.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        ResourceRepresentation
        https://www.keycloak.org/docs-api/20.0.0/rest-api/index.html#_resourcerepresentation

        :param token: client access token
        :type token: str
        :yields: Iterator over a list of ResourceRepresentations
        :rtype: Iterator[dict]
        """
        for resource_id in self.resource_set_list_ids(token):
            resource = self.resource_set_read(token, resource_id)
            yield resource
