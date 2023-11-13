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

"""User-managed access permissions module."""

from keycloak.exceptions import KeycloakPermissionFormatError, PermissionDefinitionError


class UMAPermission:
    """A class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    Usage example:

    >>> r = Resource("Users")
    >>> s = Scope("delete")
    >>> permission = r(s)
    >>> print(permission)
        'Users#delete'

    :param permission: Permission
    :type permission: UMAPermission
    :param resource: Resource
    :type resource: str
    :param scope: Scope
    :type scope: str
    """

    def __init__(self, permission=None, resource="", scope=""):
        """Init method.

        :param permission: Permission
        :type permission: UMAPermission
        :param resource: Resource
        :type resource: str
        :param scope: Scope
        :type scope: str
        :raises PermissionDefinitionError: In case bad permission definition
        """
        self.resource = resource
        self.scope = scope

        if permission:
            if not isinstance(permission, UMAPermission):
                raise PermissionDefinitionError(
                    "can't determine if '{}' is a resource or scope".format(permission)
                )
            if permission.resource:
                self.resource = str(permission.resource)
            if permission.scope:
                self.scope = str(permission.scope)

    def __str__(self):
        """Str method.

        :returns: String representation
        :rtype: str
        """
        scope = self.scope
        if scope:
            scope = "#" + scope
        return "{}{}".format(self.resource, scope)

    def __eq__(self, __o: object) -> bool:
        """Eq method.

        :param __o: The other object
        :type __o: object
        :returns: Equality boolean
        :rtype: bool
        """
        return str(self) == str(__o)

    def __repr__(self) -> str:
        """Repr method.

        :returns: The object representation
        :rtype: str
        """
        return self.__str__()

    def __hash__(self) -> int:
        """Hash method.

        :returns: Hash of the object
        :rtype: int
        """
        return hash(str(self))

    def __call__(self, permission=None, resource="", scope="") -> "UMAPermission":
        """Call method.

        :param permission: Permission
        :type permission: UMAPermission
        :param resource: Resource
        :type resource: str
        :param scope: Scope
        :type scope: str
        :returns: The combined UMA permission
        :rtype: UMAPermission
        :raises PermissionDefinitionError: In case bad permission definition
        """
        result_resource = self.resource
        result_scope = self.scope

        if resource:
            result_resource = str(resource)
        if scope:
            result_scope = str(scope)

        if permission:
            if not isinstance(permission, UMAPermission):
                raise PermissionDefinitionError(
                    "can't determine if '{}' is a resource or scope".format(permission)
                )
            if permission.resource:
                result_resource = str(permission.resource)
            if permission.scope:
                result_scope = str(permission.scope)

        return UMAPermission(resource=result_resource, scope=result_scope)


class Resource(UMAPermission):
    """A UMAPermission Resource class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    :param resource: Resource
    :type resource: str
    """

    def __init__(self, resource):
        """Init method.

        :param resource: Resource
        :type resource: str
        """
        super().__init__(resource=resource)


class Scope(UMAPermission):
    """A UMAPermission Scope class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    :param scope: Scope
    :type scope: str
    """

    def __init__(self, scope):
        """Init method.

        :param scope: Scope
        :type scope: str
        """
        super().__init__(scope=scope)


class AuthStatus:
    """A class that represents the authorization/login status of a user associated with a token.

    This has to evaluate to True if and only if the user is properly authorized
    for the requested resource.

    :param is_logged_in: Is logged in indicator
    :type is_logged_in: bool
    :param is_authorized: Is authorized indicator
    :type is_authorized: bool
    :param missing_permissions: Missing permissions
    :type missing_permissions: set
    """

    def __init__(self, is_logged_in, is_authorized, missing_permissions):
        """Init method.

        :param is_logged_in: Is logged in indicator
        :type is_logged_in: bool
        :param is_authorized: Is authorized indicator
        :type is_authorized: bool
        :param missing_permissions: Missing permissions
        :type missing_permissions: set
        """
        self.is_logged_in = is_logged_in
        self.is_authorized = is_authorized
        self.missing_permissions = missing_permissions

    def __bool__(self):
        """Bool method.

        :returns: Boolean representation
        :rtype: bool
        """
        return self.is_authorized

    def __repr__(self):
        """Repr method.

        :returns: The object representation
        :rtype: str
        """
        return (
            f"AuthStatus("
            f"is_authorized={self.is_authorized}, "
            f"is_logged_in={self.is_logged_in}, "
            f"missing_permissions={self.missing_permissions})"
        )


def build_permission_param(permissions):
    """Transform permissions to a set, so they are usable for requests.

    :param permissions: Permissions
    :type permissions: str | Iterable[str] | dict[str, str] | dict[str, Iterabble[str]]
    :returns: Permission parameters
    :rtype: set
    :raises KeycloakPermissionFormatError: In case of bad permission format
    """
    if permissions is None or permissions == "":
        return set()
    if isinstance(permissions, str):
        return set((permissions,))
    if isinstance(permissions, UMAPermission):
        return set((str(permissions),))

    try:  # treat as dictionary of permissions
        result = set()
        for resource, scopes in permissions.items():
            if scopes is None:
                result.add(resource)
            elif isinstance(scopes, str):
                result.add("{}#{}".format(resource, scopes))
            else:
                try:
                    for scope in scopes:
                        if not isinstance(scope, str):
                            raise KeycloakPermissionFormatError(
                                "misbuilt permission {}".format(permissions)
                            )
                        result.add("{}#{}".format(resource, scope))
                except TypeError:
                    raise KeycloakPermissionFormatError(
                        "misbuilt permission {}".format(permissions)
                    )
        return result
    except AttributeError:
        pass

    result = set()
    for permission in permissions:
        if not isinstance(permission, (str, UMAPermission)):
            raise KeycloakPermissionFormatError("misbuilt permission {}".format(permissions))
        result.add(str(permission))
    return result
