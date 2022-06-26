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

from typing import TYPE_CHECKING, Type, Union, Dict, Optional

import requests

if TYPE_CHECKING:
    from requests import Response
    from keycloak.keycloak_models import KeycloakModel

KeycloakErrorType = Type["KeycloakError"]
KeycloakModelType = Type["KeycloakModel"]
RequestResponseType = Union[Dict, bytes]


class KeycloakError(Exception):
    def __init__(
            self,
            error_message: Optional[str] = "",
            response_code: Optional[int] = None,
            response_body: Optional[RequestResponseType] = None
    ) -> None:

        Exception.__init__(self, error_message)

        self.response_code = response_code
        self.response_body = response_body
        self.error_message = error_message

    def __str__(self) -> str:
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


class KeycloakDeprecationError(KeycloakError):
    pass


class KeycloakGetError(KeycloakOperationError):
    pass


class KeycloakPostError(KeycloakOperationError):
    pass


class KeycloakPutError(KeycloakOperationError):
    pass


class KeycloakDeleteError(KeycloakOperationError):
    pass


class KeycloakSecretNotFound(KeycloakOperationError):
    pass


class KeycloakRPTNotFound(KeycloakOperationError):
    pass


class KeycloakAuthorizationConfigError(KeycloakOperationError):
    pass


class KeycloakInvalidTokenError(KeycloakOperationError):
    pass


class KeycloakPermissionFormatError(KeycloakOperationError):
    pass


class PermissionDefinitionError(Exception):
    pass


def raise_error_from_response(
        response: "Response",
        error: Union[KeycloakErrorType, Exception, Dict],
        expected_codes=None,
        skip_exists=False) -> RequestResponseType:
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
