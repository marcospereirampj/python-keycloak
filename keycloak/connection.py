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

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from .exceptions import *
import requests


class ConnectionManager(object):
    """ Represents a simple server connection.
    Args:
        base_url (str): The URL server
        headers (dict): The header parameters of the requests to the server.
        timeout (int): Timeout to use for requests to the server.
    """

    def __init__(self, base_url, headers={}, timeout=60):
        self.__base_url = base_url
        self.__headers = headers
        self.__timeout = timeout

    def get_url(self):
        """ Return base url in use for requests to the server. """
        return self.__base_url

    def get_timeout(self):
        """ Return timeout in use for request to the server. """
        return self.__timeout

    def set_headers(self, params):
        """ Update header request to the server.
        :arg
            params (dict): Parameters header request.
        """
        self.__headers = params

    def get_headers(self):
        """ Return header request to the server. """
        return self.__headers

    def get_param_headers(self, key):
        """ Return a single header parameter.
        :arg
            key (str): Key of the header parameters.
        :return:
            If the header parameters exist, return value him.
        """
        return self.__headers[key] if key in self.__headers.keys() else None

    def clean_headers(self):
        """ Clear header parameters. """
        self.__headers = {}

    def exist_param_headers(self, key):
        """ Check if the parameter exist in header.
        :arg
            key (str): Key of the header parameters.
        :return:
            If the header parameters exist, return True.
        """
        return True if self.get_param_headers(key) else False

    def add_param_headers(self, key, value):
        """ Add a single parameter in header.
        :arg
            key (str): Key of the header parameters.
            value (str): Value for the header parameter.
        """
        request_headers = self.__headers.copy()
        request_headers.update({key: value})
        self.set_headers(request_headers)

    def del_param_headers(self, key):
        """ Remove a single header parameter.
        :arg
            key (str): Key of the header parameters.
        """
        if self.get_param_headers(key):
            del self.__headers[key]

    def raw_get(self, path, **kwargs):
        """ Submit get request to the path.
        :arg
            path (str): Path for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """

        try:
            return requests.get(urljoin(self.get_url(), path),
                                params=kwargs,
                                headers=self.get_headers(),
                                timeout=self.get_timeout())
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def raw_post(self, path, data, **kwargs):
        """ Submit post request to the path.
        :arg
            path (str): Path for request.
            data (dict): Payload for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """
        try:
            return requests.post(urljoin(self.get_url(), path),
                                 params=kwargs,
                                 data=data,
                                 headers=self.get_headers(),
                                 timeout=self.get_timeout())
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def raw_put(self, path, data, **kwargs):
        """ Submit put request to the path.
        :arg
            path (str): Path for request.
            data (dict): Payload for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """
        try:
            return requests.put(urljoin(self.get_url(), path),
                                params=kwargs,
                                data=data,
                                headers=self.get_headers(),
                                timeout=self.get_timeout())
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)
