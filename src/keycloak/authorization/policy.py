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

"""Keycloak authorization Policy module."""

from keycloak.exceptions import KeycloakAuthorizationConfigError


class Policy:
    """
    Base policy class.

    A policy defines the conditions that must be satisfied to grant access to an object.
    Unlike permissions, you do not specify the object being protected but rather the conditions
    that must be satisfied for access to a given object (for example, resource, scope, or both).
    Policies are strongly related to the different access control mechanisms (ACMs) that you can
    use to protect your resources. With policies, you can implement strategies for attribute-based
    access control (ABAC), role-based access control (RBAC), context-based access control, or any
    combination of these.

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/policy/overview.html

    :param name: Name
    :type name: str
    :param type: Type
    :type type: str
    :param logic: Logic
    :type logic: str
    :param decision_strategy: Decision strategy
    :type decision_strategy: str

    """

    def __init__(self, name: str, type: str, logic: str, decision_strategy: str) -> None:  # noqa: A002
        """
        Init method.

        :param name: Name
        :type name: str
        :param type: Type
        :type type: str
        :param logic: Logic
        :type logic: str
        :param decision_strategy: Decision strategy
        :type decision_strategy: str
        """
        self.name = name
        self.type = type
        self.logic = logic
        self.decision_strategy = decision_strategy
        self.roles = []
        self.permissions = []

    def __repr__(self) -> str:
        """
        Repr method.

        :returns: Class representation
        :rtype: str
        """
        return f"<Policy: {self.name} ({self.type})>"

    def __str__(self) -> str:
        """
        Str method.

        :returns: Class string representation
        :rtype: str
        """
        return f"Policy: {self.name} ({self.type})"

    @property
    def name(self) -> str:
        """
        Get name.

        :returns: Name
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    @property
    def type(self) -> str:
        """
        Get type.

        :returns: Type
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, value: str) -> None:
        self._type = value

    @property
    def logic(self) -> str:
        """
        Get logic.

        :returns: Logic
        :rtype: str
        """
        return self._logic

    @logic.setter
    def logic(self, value: str) -> None:
        self._logic = value

    @property
    def decision_strategy(self) -> str:
        """
        Get decision strategy.

        :returns: Decision strategy
        :rtype: str
        """
        return self._decision_strategy

    @decision_strategy.setter
    def decision_strategy(self, value: str) -> None:
        self._decision_strategy = value

    @property
    def roles(self) -> list:
        """
        Get roles.

        :returns: Roles
        :rtype: list
        """
        return self._roles

    @roles.setter
    def roles(self, value: list) -> None:
        self._roles = value

    @property
    def permissions(self) -> list:
        """
        Get permissions.

        :returns: Permissions
        :rtype: list
        """
        return self._permissions

    @permissions.setter
    def permissions(self, value: list) -> None:
        self._permissions = value

    def add_role(self, role: dict) -> None:
        """
        Add keycloak role in policy.

        :param role: Keycloak role
        :type role: keycloak.authorization.Role
        :raises KeycloakAuthorizationConfigError: In case of misconfigured policy type
        """
        if self.type != "role":
            error_msg = "Can't add role. Policy type is different of role"
            raise KeycloakAuthorizationConfigError(error_msg)
        self._roles.append(role)

    def add_permission(self, permission: dict) -> None:
        """
        Add keycloak permission in policy.

        :param permission: Keycloak permission
        :type permission: keycloak.authorization.Permission
        """
        self._permissions.append(permission)
