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
URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE = "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/available"
URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE = "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/composite"
URL_ADMIN_USER_GROUP = "admin/realms/{realm-name}/users/{id}/groups/{group-id}"
URL_ADMIN_USER_GROUPS = "admin/realms/{realm-name}/users/{id}/groups"
URL_ADMIN_USER_PASSWORD = "admin/realms/{realm-name}/users/{id}/reset-password"
URL_ADMIN_USER_STORAGE = "admin/realms/{realm-name}/user-storage/{id}/sync"

URL_ADMIN_SERVER_INFO = "admin/serverinfo"

URL_ADMIN_GROUPS = "admin/realms/{realm-name}/groups"
URL_ADMIN_GROUP = "admin/realms/{realm-name}/groups/{id}"
URL_ADMIN_GROUP_CHILD = "admin/realms/{realm-name}/groups/{id}/children"
URL_ADMIN_GROUP_PERMISSIONS = "admin/realms/{realm-name}/groups/{id}/management/permissions"
URL_ADMIN_GROUP_MEMBERS = "admin/realms/{realm-name}/groups/{id}/members"

URL_ADMIN_CLIENTS = "admin/realms/{realm-name}/clients"
URL_ADMIN_CLIENT = "admin/realms/{realm-name}/clients/{id}"
URL_ADMIN_CLIENT_ROLES = "admin/realms/{realm-name}/clients/{id}/roles"
URL_ADMIN_CLIENT_ROLE = "admin/realms/{realm-name}/clients/{id}/roles/{role-name}"
URL_ADMIN_CLIENT_AUTHZ_SETTINGS = "admin/realms/{realm-name}/clients/{id}/authz/resource-server/settings"
URL_ADMIN_CLIENT_AUTHZ_RESOURCES = "admin/realms/{realm-name}/clients/{id}/authz/resource-server/resource"
URL_ADMIN_CLIENT_CERTS = "admin/realms/{realm-name}/clients/{id}/certificates/{attr}"

URL_ADMIN_REALM_ROLES = "admin/realms/{realm-name}/roles"
URL_ADMIN_REALM_IMPORT = "admin/realms"
URL_ADMIN_IDPS = "admin/realms/{realm-name}/identity-provider/instances"

URL_ADMIN_FLOWS = "admin/realms/{realm-name}/authentication/flows"
URL_ADMIN_FLOWS_EXECUTIONS = "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions"
