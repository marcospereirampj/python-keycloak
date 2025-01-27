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

from __future__ import annotations

from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from httpx import Response as AsyncResponse

from requests import Response

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_NOT_ALLOWED = 405
HTTP_CONFLICT = 409


class KeycloakError(Exception):
    """
    Base class for custom Keycloak errors.

    :param error_message: The error message
    :type error_message: str
    :param response_code: The response status code
    :type response_code: int
    """

    def __init__(
        self,
        error_message: str = "",
        response_code: int | None = None,
        response_body: bytes | None = None,
    ) -> None:
        """
        Init method.

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

    def __str__(self) -> str:
        """
        Str method.

        :returns: String representation of the object
        :rtype: str
        """
        if self.response_code is not None:
            return f"{self.response_code}: {self.error_message}"
        return f"{self.error_message}"


class KeycloakAuthenticationError(KeycloakError):
    """Keycloak authentication error exception."""


class KeycloakConnectionError(KeycloakError):
    """Keycloak connection error exception."""


class KeycloakOperationError(KeycloakError):
    """Keycloak operation error exception."""


class KeycloakDeprecationError(KeycloakError):
    """Keycloak deprecation error exception."""


class KeycloakGetError(KeycloakOperationError):
    """Keycloak request get error exception."""


class KeycloakPostError(KeycloakOperationError):
    """Keycloak request post error exception."""


class KeycloakPutError(KeycloakOperationError):
    """Keycloak request put error exception."""


class KeycloakDeleteError(KeycloakOperationError):
    """Keycloak request delete error exception."""


class KeycloakSecretNotFound(KeycloakOperationError):
    """Keycloak secret not found exception."""


class KeycloakRPTNotFound(KeycloakOperationError):
    """Keycloak RPT not found exception."""


class KeycloakAuthorizationConfigError(KeycloakOperationError):
    """Keycloak authorization config exception."""


class KeycloakInvalidTokenError(KeycloakOperationError):
    """Keycloak invalid token exception."""


class KeycloakPermissionFormatError(KeycloakOperationError):
    """Keycloak permission format exception."""


class PermissionDefinitionError(Exception):
    """Keycloak permission definition exception."""


def raise_error_from_response(
    response: Response | AsyncResponse,
    error: dict | Exception,
    expected_codes: list[int] | None = None,
    skip_exists: bool = False,
) -> bytes | dict | list:
    """
    Raise an exception for the response.

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
    """
    if expected_codes is None:
        expected_codes = [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT]

    if response.status_code in expected_codes:
        if response.status_code == requests.codes.no_content:
            return {}

        try:
            return response.json()
        except ValueError:
            return response.content

    if skip_exists and response.status_code == HTTP_CONFLICT:
        return {"msg": "Already exists"}

    try:
        message = response.json()["message"]
    except (KeyError, ValueError):
        message = response.content

    if isinstance(error, dict):
        error = error.get(response.status_code, KeycloakOperationError)
    elif response.status_code == HTTP_UNAUTHORIZED:
        error = KeycloakAuthenticationError

    raise error(
        error_message=message,
        response_code=response.status_code,
        response_body=response.content,
    )
