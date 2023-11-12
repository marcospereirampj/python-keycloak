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

"""Python-Keycloak library."""

from ._version import __version__
from .connection import ConnectionManager
from .exceptions import (
    KeycloakAuthenticationError,
    KeycloakAuthorizationConfigError,
    KeycloakConnectionError,
    KeycloakDeleteError,
    KeycloakDeprecationError,
    KeycloakError,
    KeycloakGetError,
    KeycloakInvalidTokenError,
    KeycloakOperationError,
    KeycloakPostError,
    KeycloakPutError,
    KeycloakRPTNotFound,
    KeycloakSecretNotFound,
)
from .keycloak_admin import KeycloakAdmin
from .keycloak_openid import KeycloakOpenID
from .keycloak_uma import KeycloakUMA
from .openid_connection import KeycloakOpenIDConnection

__all__ = [
    "__version__",
    "ConnectionManager",
    "KeycloakAuthenticationError",
    "KeycloakAuthorizationConfigError",
    "KeycloakConnectionError",
    "KeycloakDeleteError",
    "KeycloakDeprecationError",
    "KeycloakError",
    "KeycloakGetError",
    "KeycloakInvalidTokenError",
    "KeycloakOperationError",
    "KeycloakPostError",
    "KeycloakPutError",
    "KeycloakRPTNotFound",
    "KeycloakSecretNotFound",
    "KeycloakAdmin",
    "KeycloakOpenID",
    "KeycloakOpenIDConnection",
    "KeycloakUMA",
]
