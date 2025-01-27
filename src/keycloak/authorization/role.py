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

"""The authorization Role module."""

from __future__ import annotations


class Role:
    """
    Authorization Role base class.

    Roles identify a type or category of user. Admin, user,
    manager, and employee are all typical roles that may exist in an organization.

    https://keycloak.gitbooks.io/documentation/server_admin/topics/roles.html

    :param name: Name
    :type name: str
    :param required: Required role indicator
    :type required: bool
    """

    def __init__(self, name: str, required: bool = False) -> None:
        """
        Init method.

        :param name: Name
        :type name: str
        :param required: Required role indicator
        :type required: bool
        """
        self.name = name
        self.required = required

    def get_name(self) -> str:
        """
        Get name.

        :returns: Name
        :rtype: str
        """
        return self.name

    def __eq__(self, other: str | Role) -> bool:
        """
        Eq method.

        :param other: The other object
        :type other: str
        :returns: Equality bool
        :rtype: bool
        """
        if isinstance(other, str):
            return self.name == other

        if isinstance(other, Role):
            return self.name == other.name

        msg = f"Cannot compare Role with {type(other)}"
        raise NotImplementedError(msg)
