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

"""Keycloak custom exceptions module."""

import requests


class KeycloakError(Exception):
    """Base class for custom Keycloak errors.

    :param error_message: The error message
    :type error_message: str
    :param response_code: The response status code
    :type response_code: int
    """

    def __init__(self, error_message="", response_code=None, response_body=None):
        """Init method.

        :param error_message: The error message
        :type error_message: str
        :param response_code: The code of the response
        :type response_code: int
        :param response_body: Body of the response
        :type response_body: bytes
        """
        Exception.__init__(self, error_message)

        self.response_code = response_code
        self.response_body = response_body
        self.error_message = error_message

    def __str__(self):
        """Str method.

        :returns: String representation of the object
        :rtype: str
        """
        if self.response_code is not None:
            return "{0}: {1}".format(self.response_code, self.error_message)
        else:
            return "{0}".format(self.error_message)


class KeycloakAuthenticationError(KeycloakError):
    """Keycloak authentication error exception."""

    pass


class KeycloakConnectionError(KeycloakError):
    """Keycloak connection error exception."""

    pass


class KeycloakOperationError(KeycloakError):
    """Keycloak operation error exception."""

    pass


class KeycloakDeprecationError(KeycloakError):
    """Keycloak deprecation error exception."""

    pass


class KeycloakGetError(KeycloakOperationError):
    """Keycloak request get error exception."""

    pass


class KeycloakPostError(KeycloakOperationError):
    """Keycloak request post error exception."""

    pass


class KeycloakPutError(KeycloakOperationError):
    """Keycloak request put error exception."""

    pass


class KeycloakDeleteError(KeycloakOperationError):
    """Keycloak request delete error exception."""

    pass


class KeycloakSecretNotFound(KeycloakOperationError):
    """Keycloak secret not found exception."""

    pass


class KeycloakRPTNotFound(KeycloakOperationError):
    """Keycloak RPT not found exception."""

    pass


class KeycloakAuthorizationConfigError(KeycloakOperationError):
    """Keycloak authorization config exception."""

    pass


class KeycloakInvalidTokenError(KeycloakOperationError):
    """Keycloak invalid token exception."""

    pass


class KeycloakPermissionFormatError(KeycloakOperationError):
    """Keycloak permission format exception."""

    pass


class PermissionDefinitionError(Exception):
    """Keycloak permission definition exception."""

    pass


def raise_error_from_response(response, error, expected_codes=None, skip_exists=False):
    """Raise an exception for the response.

    :param response: The response object
    :type response: Response
    :param error: Error object to raise
    :type error: dict or Exception
    :param expected_codes: Set of expected codes, which should not raise the exception
    :type expected_codes: Sequence[int]
    :param skip_exists: Indicates whether the response on already existing object should be ignored
    :type skip_exists: bool

    :returns: Content of the response message
    :type: bytes or dict
    :raises KeycloakError: In case of unexpected status codes
    """  # noqa: DAR401,DAR402
    if expected_codes is None:
        expected_codes = [200, 201, 204]

    if response.status_code in expected_codes:
        if response.status_code == requests.codes.no_content:
            return {}

        try:
            return response.json()
        except ValueError:
            return response.content

    if skip_exists and response.status_code == 409:
        return {"msg": "Already exists"}

    try:
        message = response.json()["message"]
    except (KeyError, ValueError):
        message = response.content

    if isinstance(error, dict):
        error = error.get(response.status_code, KeycloakOperationError)
    else:
        if response.status_code == 401:
            error = KeycloakAuthenticationError

    raise error(
        error_message=message, response_code=response.status_code, response_body=response.content
    )
