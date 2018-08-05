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
URL_ADMIN_USER_CONSENTS = "admin/realms/{realm-name}/users/{id}/consents"
URL_ADMIN_SEND_UPDATE_ACCOUNT = "admin/realms/{realm-name}/users/{id}/execute-actions-email"
URL_ADMIN_SEND_VERIFY_EMAIL = "admin/realms/{realm-name}/users/{id}/send-verify-email"
URL_ADMIN_RESET_PASSWORD = "admin/realms/{realm-name}/users/{id}/reset-password"
URL_ADMIN_GET_SESSIONS = "admin/realms/{realm-name}/users/{id}/sessions"
URL_ADMIN_USER_CLIENT_ROLES = "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}"
URL_ADMIN_USER_GROUP = "admin/realms/{realm-name}/users/{id}/groups/{group-id}"
URL_ADMIN_USER_GROUPS = "admin/realms/{realm-name}/users/{id}/groups"
URL_ADMIN_USER_PASSWORD = "admin/realms/{realm-name}/users/{id}/reset-password"

URL_ADMIN_SERVER_INFO = "admin/serverinfo"

URL_ADMIN_GROUPS = "admin/realms/{realm-name}/groups"
URL_ADMIN_GROUP = "admin/realms/{realm-name}/groups/{id}"
URL_ADMIN_GROUP_CHILD = "admin/realms/{realm-name}/groups/{id}/children"
URL_ADMIN_GROUP_PERMISSIONS = "admin/realms/{realm-name}/groups/{id}/management/permissions"

URL_ADMIN_CLIENTS = "admin/realms/{realm-name}/clients"
URL_ADMIN_CLIENT = "admin/realms/{realm-name}/clients/{id}"
URL_ADMIN_CLIENT_ROLES = "admin/realms/{realm-name}/clients/{id}/roles"
URL_ADMIN_CLIENT_ROLE = "admin/realms/{realm-name}/clients/{id}/roles/{role-name}"

URL_ADMIN_REALM_ROLES = "admin/realms/{realm-name}/roles"

URL_ADMIN_USER_STORAGE = "admin/realms/{realm-name}/user-storage/{id}/sync"

URL_ADMIN_IDPS = "admin/realms/{realm}/identity-provider/instances"
