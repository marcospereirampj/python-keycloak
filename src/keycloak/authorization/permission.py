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

"""Keycloak authorization Permission module."""


class Permission:
    """
    Base permission class.

    Consider this simple and very common permission:

    A permission associates the object being protected with the policies that must be evaluated to
    determine whether access is granted.

    X CAN DO Y ON RESOURCE Z

    where

    - X represents one or more users, roles, or groups, or a combination of them. You can
        also use claims and context here.

    - Y represents an action to be performed, for example, write, view, and so on.

    - Z represents a protected resource, for example, "/accounts".

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/permission/overview.html

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
        self.resources = []
        self.scopes = []

    def __repr__(self) -> str:
        """
        Repr method.

        :returns: Class representation
        :rtype: str
        """
        return f"<Permission: {self.name} ({self.type})>"

    def __str__(self) -> str:
        """
        Str method.

        :returns: Class string representation
        :rtype: str
        """
        return f"Permission: {self.name} ({self.type})"

    @property
    def name(self) -> str:
        """
        Get name.

        :returns: name
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

        :returns: type
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
    def logic(self, value: str) -> str:
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
    def resources(self) -> list:
        """
        Get resources.

        :returns: Resources
        :rtype: list
        """
        return self._resources

    @resources.setter
    def resources(self, value: list) -> None:
        self._resources = value

    @property
    def scopes(self) -> list:
        """
        Get scopes.

        :returns: Scopes
        :rtype: list
        """
        return self._scopes

    @scopes.setter
    def scopes(self, value: list) -> None:
        self._scopes = value
