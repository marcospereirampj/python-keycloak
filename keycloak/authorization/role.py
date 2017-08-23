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


class Role:
    """
    Roles identify a type or category of user. Admin, user,
    manager, and employee are all typical roles that may exist in an organization.

    https://keycloak.gitbooks.io/documentation/server_admin/topics/roles.html

    """

    def __init__(self, name, required=False):
        self.name = name
        self.required = required

    @property
    def get_name(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, str):
            return self.name == other
        return NotImplemented
