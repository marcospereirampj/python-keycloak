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

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

import requests
from requests.adapters import HTTPAdapter

from .exceptions import KeycloakConnectionError


class ConnectionManager(object):
    """
    Represents a simple server connection.

    :param base_url: (str) The server URL.
    :param headers: (dict) The header parameters of the requests to the server.
    :param timeout: (int) Timeout to use for requests to the server.
    :param verify: (bool) Verify server SSL.
    :param proxies: (dict) The proxies servers requests is sent by.
    """

    def __init__(self, base_url, headers={}, timeout=60, verify=True, proxies=None):
        self._base_url = base_url
        self._headers = headers
        self._timeout = timeout
        self._verify = verify
        self._s = requests.Session()
        self._s.auth = lambda x: x  # don't let requests add auth headers

        # retry once to reset connection with Keycloak after  tomcat's ConnectionTimeout
        # see https://github.com/marcospereirampj/python-keycloak/issues/36
        for protocol in ("https://", "http://"):
            adapter = HTTPAdapter(max_retries=1)
            # adds POST to retry whitelist
            allowed_methods = set(adapter.max_retries.allowed_methods)
            allowed_methods.add("POST")
            adapter.max_retries.allowed_methods = frozenset(allowed_methods)

            self._s.mount(protocol, adapter)

        if proxies:
            self._s.proxies.update(proxies)

    def __del__(self):
        self._s.close()

    @property
    def base_url(self):
        """Return base url in use for requests to the server."""
        return self._base_url

    @base_url.setter
    def base_url(self, value):
        """ """
        self._base_url = value

    @property
    def timeout(self):
        """Return timeout in use for request to the server."""
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        """ """
        self._timeout = value

    @property
    def verify(self):
        """Return verify in use for request to the server."""
        return self._verify

    @verify.setter
    def verify(self, value):
        """ """
        self._verify = value

    @property
    def headers(self):
        """Return header request to the server."""
        return self._headers

    @headers.setter
    def headers(self, value):
        """ """
        self._headers = value

    def param_headers(self, key):
        """
        Return a specific header parameter.

        :param key: (str) Header parameters key.
        :returns: If the header parameters exist, return its value.
        """
        return self.headers.get(key)

    def clean_headers(self):
        """Clear header parameters."""
        self.headers = {}

    def exist_param_headers(self, key):
        """Check if the parameter exists in the header.

        :param key: (str) Header parameters key.
        :returns: If the header parameters exist, return True.
        """
        return self.param_headers(key) is not None

    def add_param_headers(self, key, value):
        """Add a single parameter inside the header.

        :param key: (str) Header parameters key.
        :param value: (str) Value to be added.
        """
        self.headers[key] = value

    def del_param_headers(self, key):
        """Remove a specific parameter.

        :param key: (str) Key of the header parameters.
        """
        self.headers.pop(key, None)

    def raw_get(self, path, **kwargs):
        """Submit get request to the path.

        :param path: (str) Path for request.
        :returns: Response the request.
        :raises: HttpError Can't connect to server.
        """

        try:
            return self._s.get(
                urljoin(self.base_url, path),
                params=kwargs,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            raise KeycloakConnectionError("Can't connect to server (%s)" % e)

    def raw_post(self, path, data, **kwargs):
        """Submit post request to the path.

        :param path: (str) Path for request.
        :param data: (dict) Payload for request.
        :returns: Response the request.
        :raises: HttpError Can't connect to server.
        """
        try:
            return self._s.post(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            raise KeycloakConnectionError("Can't connect to server (%s)" % e)

    def raw_put(self, path, data, **kwargs):
        """Submit put request to the path.

        :param path: (str) Path for request.
        :param data: (dict) Payload for request.
        :returns: Response the request.
        :raises: HttpError Can't connect to server.
        """
        try:
            return self._s.put(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            raise KeycloakConnectionError("Can't connect to server (%s)" % e)

    def raw_delete(self, path, data={}, **kwargs):
        """Submit delete request to the path.

        :param path: (str) Path for request.
        :param data: (dict) Payload for request.
        :returns: Response the request.
        :raises: HttpError Can't connect to server.
        """
        try:
            return self._s.delete(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            raise KeycloakConnectionError("Can't connect to server (%s)" % e)
