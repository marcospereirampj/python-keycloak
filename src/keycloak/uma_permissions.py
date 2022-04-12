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

from keycloak.exceptions import KeycloakPermissionFormatError, PermissionDefinitionError


class UMAPermission:
    """A class to conveniently assembly permissions.
    The class itself is callable, and will return the assembled permission.

    Usage example:

    >>> r = Resource("Users")
    >>> s = Scope("delete")
    >>> permission = r(s)
    >>> print(permission)
        'Users#delete'

    """

    def __init__(self, *, resource="", scope=""):
        self.resource = resource
        self.scope = scope

    def __str__(self):
        scope = self.scope
        if scope:
            scope = "#" + scope
        return "{}{}".format(self.resource, scope)

    def __eq__(self, __o: object) -> bool:
        return str(self) == str(__o)

    def __repr__(self) -> str:
        return self.__str__()

    def __hash__(self) -> int:
        return hash(str(self))

    def __call__(self, *args, resource="", scope="") -> object:
        result_resource = self.resource
        result_scope = self.scope

        for arg in args:
            if not isinstance(arg, UMAPermission):
                raise PermissionDefinitionError(
                    "can't determine if '{}' is a resource or scope".format(arg)
                )
            if arg.resource:
                result_resource = str(arg.resource)
            if arg.scope:
                result_scope = str(arg.scope)

        if resource:
            result_resource = str(resource)
        if scope:
            result_scope = str(scope)

        return UMAPermission(resource=result_resource, scope=result_scope)


class Resource(UMAPermission):
    def __init__(self, resource):
        super().__init__(resource=resource)


class Scope(UMAPermission):
    def __init__(self, scope):
        super().__init__(scope=scope)


class AuthStatus:
    """A class that represents the authorization/login status of a user associated with a token.
    This has to evaluate to True if and only if the user is properly authorized for the requested resource."""

    def __init__(self, is_logged_in, is_authorized, missing_permissions):
        self.is_logged_in = is_logged_in
        self.is_authorized = is_authorized
        self.missing_permissions = missing_permissions

    def __bool__(self):
        return self.is_authorized

    def __repr__(self):
        return f"AuthStatus(is_authorized={self.is_authorized}, is_logged_in={self.is_logged_in}, missing_permissions={self.missing_permissions})"


def build_permission_param(permissions):
    """
    Transform permissions to a set, so they are usable for requests

    :param permissions: either str (resource#scope),
        iterable[str] (resource#scope),
        dict[str,str] (resource: scope),
        dict[str,iterable[str]] (resource: scopes)
    :return: result bool
    """
    if permissions is None or permissions == "":
        return set()
    if isinstance(permissions, (str, UMAPermission)):
        return set((permissions,))

    try:  # treat as dictionary of permissions
        result = set()
        for resource, scopes in permissions.items():
            if scopes is None:
                result.add(resource)
            elif isinstance(scopes, (str, UMAPermission)):
                result.add("{}#{}".format(resource, scopes))
            else:
                for scope in scopes:
                    if not isinstance(scope, (str, UMAPermission)):
                        raise KeycloakPermissionFormatError(
                            "misbuilt permission {}".format(permissions)
                        )
                    result.add("{}#{}".format(resource, scope))
        return result
    except AttributeError:
        pass

    try:  # treat as any other iterable of permissions
        return set(permissions)
    except TypeError:
        pass
    raise KeycloakPermissionFormatError("misbuilt permission {}".format(permissions))
