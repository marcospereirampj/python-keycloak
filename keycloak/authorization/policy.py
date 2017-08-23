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

from ..exceptions import KeycloakAuthorizationConfigError


class Policy:
    """
    A policy defines the conditions that must be satisfied to grant access to an object.
    Unlike permissions, you do not specify the object being protected but rather the conditions
    that must be satisfied for access to a given object (for example, resource, scope, or both).
    Policies are strongly related to the different access control mechanisms (ACMs) that you can use to
    protect your resources. With policies, you can implement strategies for attribute-based access control
    (ABAC), role-based access control (RBAC), context-based access control, or any combination of these.

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/policy/overview.html

    """

    def __init__(self, name, type, logic, decision_strategy):
        self._name = name
        self._type = type
        self._logic = logic
        self._decision_strategy = decision_strategy
        self._roles = []
        self._permissions = []

    def __repr__(self):
        return "<Policy: %s (%s)>" % (self.name, self.type)

    def __str__(self):
        return "Policy: %s (%s)" % (self.name, self.type)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def logic(self):
        return self._logic

    @logic.setter
    def logic(self, value):
        self._logic = value

    @property
    def decision_strategy(self):
        return self._decision_strategy

    @decision_strategy.setter
    def decision_strategy(self, value):
        self._decision_strategy = value

    @property
    def roles(self):
        return self._roles

    @property
    def permissions(self):
        return self._permissions

    def add_role(self, role):
        """
        Add keycloak role in policy.

        :param role: keycloak role.
        :return:
        """
        if self.type != 'role':
            raise KeycloakAuthorizationConfigError(
                "Can't add role. Policy type is different of role")
        self._roles.append(role)

    def add_permission(self, permission):
        """
        Add keycloak permission in policy.

        :param permission: keycloak permission.
        :return:
        """
        self._permissions.append(permission)
