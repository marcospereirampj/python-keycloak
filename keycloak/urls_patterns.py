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
URL_REALM = "realms/{realm-name}"
URL_WELL_KNOWN = "realms/{realm-name}/.well-known/openid-configuration"
URL_TOKEN = "realms/{realm-name}/protocol/openid-connect/token"
URL_USERINFO = "realms/{realm-name}/protocol/openid-connect/userinfo"
URL_LOGOUT = "realms/{realm-name}/protocol/openid-connect/logout"
URL_CERTS = "realms/{realm-name}/protocol/openid-connect/certs"
URL_INTROSPECT = "realms/{realm-name}/protocol/openid-connect/token/introspect"
URL_ENTITLEMENT = "realms/{realm-name}/authz/entitlement/{resource-server-id}"
URL_AUTH = (
    "{authorization-endpoint}?client_id={client-id}&response_type=code&redirect_uri={redirect-uri}"
)

# ADMIN URLS
URL_ADMIN_USERS = "admin/realms/{realm-name}/users"
URL_ADMIN_USERS_COUNT = "admin/realms/{realm-name}/users/count"
URL_ADMIN_USER = "admin/realms/{realm-name}/users/{id}"
URL_ADMIN_USER_CONSENTS = "admin/realms/{realm-name}/users/{id}/consents"
URL_ADMIN_SEND_UPDATE_ACCOUNT = "admin/realms/{realm-name}/users/{id}/execute-actions-email"
URL_ADMIN_SEND_VERIFY_EMAIL = "admin/realms/{realm-name}/users/{id}/send-verify-email"
URL_ADMIN_RESET_PASSWORD = "admin/realms/{realm-name}/users/{id}/reset-password"
URL_ADMIN_GET_SESSIONS = "admin/realms/{realm-name}/users/{id}/sessions"
URL_ADMIN_USER_CLIENT_ROLES = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}"
)
URL_ADMIN_USER_REALM_ROLES = "admin/realms/{realm-name}/users/{id}/role-mappings/realm"
URL_ADMIN_USER_REALM_ROLES_AVAILABLE = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/realm/available"
)
URL_ADMIN_USER_REALM_ROLES_COMPOSITE = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/realm/composite"
)
URL_ADMIN_GROUPS_REALM_ROLES = "admin/realms/{realm-name}/groups/{id}/role-mappings/realm"
URL_ADMIN_GROUPS_CLIENT_ROLES = (
    "admin/realms/{realm-name}/groups/{id}/role-mappings/clients/{client-id}"
)
URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/available"
)
URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/composite"
)
URL_ADMIN_USER_GROUP = "admin/realms/{realm-name}/users/{id}/groups/{group-id}"
URL_ADMIN_USER_GROUPS = "admin/realms/{realm-name}/users/{id}/groups"
URL_ADMIN_USER_CREDENTIALS = "admin/realms/{realm-name}/users/{id}/credentials"
URL_ADMIN_USER_CREDENTIAL = "admin/realms/{realm-name}/users/{id}/credentials/{credential_id}"
URL_ADMIN_USER_LOGOUT = "admin/realms/{realm-name}/users/{id}/logout"
URL_ADMIN_USER_STORAGE = "admin/realms/{realm-name}/user-storage/{id}/sync"

URL_ADMIN_SERVER_INFO = "admin/serverinfo"

URL_ADMIN_GROUPS = "admin/realms/{realm-name}/groups"
URL_ADMIN_GROUP = "admin/realms/{realm-name}/groups/{id}"
URL_ADMIN_GROUP_CHILD = "admin/realms/{realm-name}/groups/{id}/children"
URL_ADMIN_GROUP_PERMISSIONS = "admin/realms/{realm-name}/groups/{id}/management/permissions"
URL_ADMIN_GROUP_MEMBERS = "admin/realms/{realm-name}/groups/{id}/members"

URL_ADMIN_CLIENTS = "admin/realms/{realm-name}/clients"
URL_ADMIN_CLIENT = URL_ADMIN_CLIENTS + "/{id}"
URL_ADMIN_CLIENT_ALL_SESSIONS = URL_ADMIN_CLIENT + "/user-sessions"
URL_ADMIN_CLIENT_SECRETS = URL_ADMIN_CLIENT + "/client-secret"
URL_ADMIN_CLIENT_ROLES = URL_ADMIN_CLIENT + "/roles"
URL_ADMIN_CLIENT_ROLE = URL_ADMIN_CLIENT + "/roles/{role-name}"
URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE = URL_ADMIN_CLIENT_ROLE + "/composites"
URL_ADMIN_CLIENT_ROLE_MEMBERS = URL_ADMIN_CLIENT + "/roles/{role-name}/users"
URL_ADMIN_CLIENT_ROLE_GROUPS = URL_ADMIN_CLIENT + "/roles/{role-name}/groups"

URL_ADMIN_CLIENT_AUTHZ_SETTINGS = URL_ADMIN_CLIENT + "/authz/resource-server/settings"
URL_ADMIN_CLIENT_AUTHZ_RESOURCES = URL_ADMIN_CLIENT + "/authz/resource-server/resource?max=-1"
URL_ADMIN_CLIENT_AUTHZ_SCOPES = URL_ADMIN_CLIENT + "/authz/resource-server/scope?max=-1"
URL_ADMIN_CLIENT_AUTHZ_PERMISSIONS = URL_ADMIN_CLIENT + "/authz/resource-server/permission?max=-1"
URL_ADMIN_CLIENT_AUTHZ_POLICIES = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy?max=-1&permission=false"
)
URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy/role?max=-1"
)
URL_ADMIN_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION = (
    URL_ADMIN_CLIENT + "/authz/resource-server/permission/resource?max=-1"
)

URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER = URL_ADMIN_CLIENT + "/service-account-user"
URL_ADMIN_CLIENT_CERTS = URL_ADMIN_CLIENT + "/certificates/{attr}"
URL_ADMIN_CLIENT_INSTALLATION_PROVIDER = URL_ADMIN_CLIENT + "/installation/providers/{provider-id}"
URL_ADMIN_CLIENT_PROTOCOL_MAPPERS = URL_ADMIN_CLIENT + "/protocol-mappers/models"
URL_ADMIN_CLIENT_PROTOCOL_MAPPER = URL_ADMIN_CLIENT_PROTOCOL_MAPPERS + "/{protocol-mapper-id}"

URL_ADMIN_CLIENT_SCOPES = "admin/realms/{realm-name}/client-scopes"
URL_ADMIN_CLIENT_SCOPE = URL_ADMIN_CLIENT_SCOPES + "/{scope-id}"
URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER = URL_ADMIN_CLIENT_SCOPE + "/protocol-mappers/models"
URL_ADMIN_CLIENT_SCOPES_MAPPERS = URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER + "/{protocol-mapper-id}"

URL_ADMIN_REALM_ROLES = "admin/realms/{realm-name}/roles"
URL_ADMIN_REALM_ROLES_MEMBERS = URL_ADMIN_REALM_ROLES + "/{role-name}/users"
URL_ADMIN_REALMS = "admin/realms"
URL_ADMIN_REALM = "admin/realms/{realm-name}"
URL_ADMIN_IDPS = "admin/realms/{realm-name}/identity-provider/instances"
URL_ADMIN_IDP_MAPPERS = "admin/realms/{realm-name}/identity-provider/instances/{idp-alias}/mappers"
URL_ADMIN_IDP = "admin/realms//{realm-name}/identity-provider/instances/{alias}"
URL_ADMIN_REALM_ROLES_ROLE_BY_NAME = "admin/realms/{realm-name}/roles/{role-name}"
URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE = (
    "admin/realms/{realm-name}/roles/{role-name}/composites"
)
URL_ADMIN_REALM_EXPORT = (
    "admin/realms/{realm-name}/partial-export?exportClients={export-clients}&"
    + "exportGroupsAndRoles={export-groups-and-roles}"
)

URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES = URL_ADMIN_REALM + "/default-default-client-scopes"
URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE = URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES + "/{id}"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES = URL_ADMIN_REALM + "/default-optional-client-scopes"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE = URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES + "/{id}"

URL_ADMIN_FLOWS = "admin/realms/{realm-name}/authentication/flows"
URL_ADMIN_FLOW = URL_ADMIN_FLOWS + "/{id}"
URL_ADMIN_FLOWS_ALIAS = "admin/realms/{realm-name}/authentication/flows/{flow-id}"
URL_ADMIN_FLOWS_COPY = "admin/realms/{realm-name}/authentication/flows/{flow-alias}/copy"
URL_ADMIN_FLOWS_EXECUTIONS = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions"
)
URL_ADMIN_FLOWS_EXECUTION = "admin/realms/{realm-name}/authentication/executions/{id}"
URL_ADMIN_FLOWS_EXECUTIONS_EXECUTION = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions/execution"
)
URL_ADMIN_FLOWS_EXECUTIONS_FLOW = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions/flow"
)
URL_ADMIN_AUTHENTICATOR_PROVIDERS = (
    "admin/realms/{realm-name}/authentication/authenticator-providers"
)
URL_ADMIN_AUTHENTICATOR_CONFIG_DESCRIPTION = (
    "admin/realms/{realm-name}/authentication/config-description/{provider-id}"
)
URL_ADMIN_AUTHENTICATOR_CONFIG = "admin/realms/{realm-name}/authentication/config/{id}"

URL_ADMIN_COMPONENTS = "admin/realms/{realm-name}/components"
URL_ADMIN_COMPONENT = "admin/realms/{realm-name}/components/{component-id}"
URL_ADMIN_KEYS = "admin/realms/{realm-name}/keys"

URL_ADMIN_USER_FEDERATED_IDENTITIES = "admin/realms/{realm-name}/users/{id}/federated-identity"
URL_ADMIN_USER_FEDERATED_IDENTITY = (
    "admin/realms/{realm-name}/users/{id}/federated-identity/{provider}"
)

URL_ADMIN_EVENTS = "admin/realms/{realm-name}/events"
URL_ADMIN_CLIENT_SESSION_STATS = "admin/realms/{realm-name}/client-session-stats"
