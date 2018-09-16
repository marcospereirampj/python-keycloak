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


class Permission:
    """
    Consider this simple and very common permission:

    A permission associates the object being protected with the policies that must be evaluated to determine whether access is granted.

    X CAN DO Y ON RESOURCE Z

    where …
        X represents one or more users, roles, or groups, or a combination of them. You can
        also use claims and context here.
        Y represents an action to be performed, for example, write, view, and so on.
        Z represents a protected resource, for example, "/accounts".

    https://keycloak.gitbooks.io/documentation/authorization_services/topics/permission/overview.html

    """

    def __init__(self, name, type, logic, decision_strategy):
        self._name = name
        self._type = type
        self._logic = logic
        self._decision_strategy = decision_strategy
        self._resources = []
        self._scopes = []

    def __repr__(self):
        return "<Permission: %s (%s)>" % (self.name, self.type)

    def __str__(self):
        return "Permission: %s (%s)" % (self.name, self.type)

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
    def resources(self):
        return self._resources

    @resources.setter
    def resources(self, value):
        self._resources = value

    @property
    def scopes(self):
        return self._scopes

    @scopes.setter
    def scopes(self, value):
        self._scopes = value
