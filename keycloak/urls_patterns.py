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

# OPENID URLS
URL_WELL_KNOWN = "realms/{realm-name}/.well-known/openid-configuration"
URL_TOKEN = "realms/{realm-name}/protocol/openid-connect/token"
URL_USERINFO = "realms/{realm-name}/protocol/openid-connect/userinfo"
URL_LOGOUT = "realms/{realm-name}/protocol/openid-connect/logout"
URL_CERTS = "realms/{realm-name}/protocol/openid-connect/certs"
URL_INTROSPECT = "realms/{realm-name}/protocol/openid-connect/token/introspect"
URL_ENTITLEMENT = "realms/{realm-name}/authz/entitlement/{resource-server-id}"

# ADMIN URLS
URL_ADMIN_USERS = "admin/realms/{realm-name}/users"
URL_ADMIN_USERS_COUNT = "admin/realms/{realm-name}/users/count"
URL_ADMIN_USER = "admin/realms/{realm-name}/users/{id}"
