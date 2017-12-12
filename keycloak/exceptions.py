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

import requests


class KeycloakError(Exception):
    def __init__(self, error_message="", response_code=None,
                 response_body=None):

        Exception.__init__(self, error_message)

        self.response_code = response_code
        self.response_body = response_body
        self.error_message = error_message

    def __str__(self):
        if self.response_code is not None:
            return "{0}: {1}".format(self.response_code, self.error_message)
        else:
            return "{0}".format(self.error_message)


class KeycloakAuthenticationError(KeycloakError):
    pass


class KeycloakConnectionError(KeycloakError):
    pass


class KeycloakOperationError(KeycloakError):
    pass


class KeycloakGetError(KeycloakOperationError):
    pass


class KeycloakSecretNotFound(KeycloakOperationError):
    pass


class KeycloakRPTNotFound(KeycloakOperationError):
    pass


class KeycloakAuthorizationConfigError(KeycloakOperationError):
    pass


class KeycloakInvalidTokenError(KeycloakOperationError):
    pass


def raise_error_from_response(response, error, expected_code=200):

    if expected_code == response.status_code:
        if expected_code == requests.codes.no_content:
            return {}
        try:
            return response.json()
        except ValueError:
            return response.content

    try:
        message = response.json()['message']
    except (KeyError, ValueError):
        message = response.content

    if isinstance(error, dict):
        error = error.get(response.status_code, KeycloakOperationError)
    else:
        if response.status_code == 401:
            error = KeycloakAuthenticationError

    raise error(error_message=message,
                response_code=response.status_code,
                response_body=response.content)
