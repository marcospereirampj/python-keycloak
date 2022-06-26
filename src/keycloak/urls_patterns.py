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
URL_REALM: str = "realms/{realm-name}"
URL_WELL_KNOWN: str = "realms/{realm-name}/.well-known/openid-configuration"
URL_TOKEN: str = "realms/{realm-name}/protocol/openid-connect/token"
URL_USERINFO: str = "realms/{realm-name}/protocol/openid-connect/userinfo"
URL_LOGOUT: str = "realms/{realm-name}/protocol/openid-connect/logout"
URL_CERTS: str = "realms/{realm-name}/protocol/openid-connect/certs"
URL_INTROSPECT: str = "realms/{realm-name}/protocol/openid-connect/token/introspect"
URL_ENTITLEMENT: str = "realms/{realm-name}/authz/entitlement/{resource-server-id}"
URL_AUTH: str = (
    "{authorization-endpoint}?client_id={client-id}&response_type=code&redirect_uri={redirect-uri}"
)

# ADMIN URLS
URL_ADMIN_USERS: str = "admin/realms/{realm-name}/users"
URL_ADMIN_USERS_COUNT: str = "admin/realms/{realm-name}/users/count"
URL_ADMIN_USER: str = "admin/realms/{realm-name}/users/{id}"
URL_ADMIN_USER_CONSENTS: str = "admin/realms/{realm-name}/users/{id}/consents"
URL_ADMIN_SEND_UPDATE_ACCOUNT: str = "admin/realms/{realm-name}/users/{id}/execute-actions-email"
URL_ADMIN_SEND_VERIFY_EMAIL: str = "admin/realms/{realm-name}/users/{id}/send-verify-email"
URL_ADMIN_RESET_PASSWORD: str = "admin/realms/{realm-name}/users/{id}/reset-password"
URL_ADMIN_GET_SESSIONS: str = "admin/realms/{realm-name}/users/{id}/sessions"
URL_ADMIN_USER_CLIENT_ROLES: str = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}"
)
URL_ADMIN_USER_REALM_ROLES: str = "admin/realms/{realm-name}/users/{id}/role-mappings/realm"
URL_ADMIN_USER_REALM_ROLES_AVAILABLE: str = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/realm/available"
)
URL_ADMIN_USER_REALM_ROLES_COMPOSITE: str = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/realm/composite"
)
URL_ADMIN_GROUPS_REALM_ROLES: str = "admin/realms/{realm-name}/groups/{id}/role-mappings/realm"
URL_ADMIN_GROUPS_CLIENT_ROLES: str = (
    "admin/realms/{realm-name}/groups/{id}/role-mappings/clients/{client-id}"
)
URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE: str = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/available"
)
URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE: str = (
    "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/composite"
)
URL_ADMIN_USER_GROUP: str = "admin/realms/{realm-name}/users/{id}/groups/{group-id}"
URL_ADMIN_USER_GROUPS: str = "admin/realms/{realm-name}/users/{id}/groups"
URL_ADMIN_USER_CREDENTIALS: str = "admin/realms/{realm-name}/users/{id}/credentials"
URL_ADMIN_USER_CREDENTIAL: str = "admin/realms/{realm-name}/users/{id}/credentials/{credential_id}"
URL_ADMIN_USER_LOGOUT: str = "admin/realms/{realm-name}/users/{id}/logout"
URL_ADMIN_USER_STORAGE: str = "admin/realms/{realm-name}/user-storage/{id}/sync"

URL_ADMIN_SERVER_INFO: str = "admin/serverinfo"

URL_ADMIN_GROUPS: str = "admin/realms/{realm-name}/groups"
URL_ADMIN_GROUP: str = "admin/realms/{realm-name}/groups/{id}"
URL_ADMIN_GROUP_CHILD: str = "admin/realms/{realm-name}/groups/{id}/children"
URL_ADMIN_GROUP_PERMISSIONS: str = "admin/realms/{realm-name}/groups/{id}/management/permissions"
URL_ADMIN_GROUP_MEMBERS: str = "admin/realms/{realm-name}/groups/{id}/members"

URL_ADMIN_CLIENTS: str = "admin/realms/{realm-name}/clients"
URL_ADMIN_CLIENT: str = URL_ADMIN_CLIENTS + "/{id}"
URL_ADMIN_CLIENT_ALL_SESSIONS: str = URL_ADMIN_CLIENT + "/user-sessions"
URL_ADMIN_CLIENT_SECRETS: str = URL_ADMIN_CLIENT + "/client-secret"
URL_ADMIN_CLIENT_ROLES: str = URL_ADMIN_CLIENT + "/roles"
URL_ADMIN_CLIENT_ROLE: str = URL_ADMIN_CLIENT + "/roles/{role-name}"
URL_ADMIN_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE: str = URL_ADMIN_CLIENT_ROLE + "/composites"
URL_ADMIN_CLIENT_ROLE_MEMBERS: str = URL_ADMIN_CLIENT + "/roles/{role-name}/users"
URL_ADMIN_CLIENT_ROLE_GROUPS: str = URL_ADMIN_CLIENT + "/roles/{role-name}/groups"
URL_ADMIN_CLIENT_MANAGEMENT_PERMISSIONS: str = URL_ADMIN_CLIENT + "/management/permissions"

URL_ADMIN_CLIENT_AUTHZ_SETTINGS: str = URL_ADMIN_CLIENT + "/authz/resource-server/settings"
URL_ADMIN_CLIENT_AUTHZ_RESOURCES: str = URL_ADMIN_CLIENT + "/authz/resource-server/resource?max=-1"
URL_ADMIN_CLIENT_AUTHZ_SCOPES: str = URL_ADMIN_CLIENT + "/authz/resource-server/scope?max=-1"
URL_ADMIN_CLIENT_AUTHZ_PERMISSIONS: str = URL_ADMIN_CLIENT + "/authz/resource-server/permission?max=-1"
URL_ADMIN_CLIENT_AUTHZ_POLICIES: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy?max=-1&permission=false"
)
URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy/role?max=-1"
)
URL_ADMIN_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/permission/resource?max=-1"
)
URL_ADMIN_CLIENT_AUTHZ_POLICY_SCOPES: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy/{policy-id}/scopes"
)
URL_ADMIN_CLIENT_AUTHZ_POLICY_RESOURCES: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy/{policy-id}/resources"
)
URL_ADMIN_CLIENT_AUTHZ_SCOPE_PERMISSION: str = (
    URL_ADMIN_CLIENT + "/authz/resource-server/permission/scope/{scope-id}"
)
URL_ADMIN_CLIENT_AUTHZ_CLIENT_POLICY: str = URL_ADMIN_CLIENT + "/authz/resource-server/policy/client"

URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER: str = URL_ADMIN_CLIENT + "/service-account-user"
URL_ADMIN_CLIENT_CERTS: str = URL_ADMIN_CLIENT + "/certificates/{attr}"
URL_ADMIN_CLIENT_INSTALLATION_PROVIDER: str = URL_ADMIN_CLIENT + "/installation/providers/{provider-id}"
URL_ADMIN_CLIENT_PROTOCOL_MAPPERS: str = URL_ADMIN_CLIENT + "/protocol-mappers/models"
URL_ADMIN_CLIENT_PROTOCOL_MAPPER: str = URL_ADMIN_CLIENT_PROTOCOL_MAPPERS + "/{protocol-mapper-id}"

URL_ADMIN_CLIENT_SCOPES: str = "admin/realms/{realm-name}/client-scopes"
URL_ADMIN_CLIENT_SCOPE: str = URL_ADMIN_CLIENT_SCOPES + "/{scope-id}"
URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER: str = URL_ADMIN_CLIENT_SCOPE + "/protocol-mappers/models"
URL_ADMIN_CLIENT_SCOPES_MAPPERS: str = URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER + "/{protocol-mapper-id}"

URL_ADMIN_REALM_ROLES: str = "admin/realms/{realm-name}/roles"
URL_ADMIN_REALM_ROLES_MEMBERS: str = URL_ADMIN_REALM_ROLES + "/{role-name}/users"
URL_ADMIN_REALMS: str = "admin/realms"
URL_ADMIN_REALM: str = "admin/realms/{realm-name}"
URL_ADMIN_IDPS: str = "admin/realms/{realm-name}/identity-provider/instances"
URL_ADMIN_IDP_MAPPERS: str = "admin/realms/{realm-name}/identity-provider/instances/{idp-alias}/mappers"
URL_ADMIN_IDP_MAPPER_UPDATE: str = URL_ADMIN_IDP_MAPPERS + "/{mapper-id}"
URL_ADMIN_IDP: str = "admin/realms//{realm-name}/identity-provider/instances/{alias}"
URL_ADMIN_REALM_ROLES_ROLE_BY_NAME: str = "admin/realms/{realm-name}/roles/{role-name}"
URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE: str = (
    "admin/realms/{realm-name}/roles/{role-name}/composites"
)
URL_ADMIN_REALM_EXPORT: str = (
    "admin/realms/{realm-name}/partial-export?exportClients={export-clients}&"
    + "exportGroupsAndRoles={export-groups-and-roles}"
)

URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES: str = URL_ADMIN_REALM + "/default-default-client-scopes"
URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE: str = URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES + "/{id}"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES: str = URL_ADMIN_REALM + "/default-optional-client-scopes"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE: str = URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES + "/{id}"

URL_ADMIN_FLOWS: str = "admin/realms/{realm-name}/authentication/flows"
URL_ADMIN_FLOW: str = URL_ADMIN_FLOWS + "/{id}"
URL_ADMIN_FLOWS_ALIAS: str = "admin/realms/{realm-name}/authentication/flows/{flow-id}"
URL_ADMIN_FLOWS_COPY: str = "admin/realms/{realm-name}/authentication/flows/{flow-alias}/copy"
URL_ADMIN_FLOWS_EXECUTIONS: str = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions"
)
URL_ADMIN_FLOWS_EXECUTION: str = "admin/realms/{realm-name}/authentication/executions/{id}"
URL_ADMIN_FLOWS_EXECUTIONS_EXECUTION: str = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions/execution"
)
URL_ADMIN_FLOWS_EXECUTIONS_FLOW: str = (
    "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions/flow"
)
URL_ADMIN_AUTHENTICATOR_PROVIDERS: str = (
    "admin/realms/{realm-name}/authentication/authenticator-providers"
)
URL_ADMIN_AUTHENTICATOR_CONFIG_DESCRIPTION: str = (
    "admin/realms/{realm-name}/authentication/config-description/{provider-id}"
)
URL_ADMIN_AUTHENTICATOR_CONFIG: str = "admin/realms/{realm-name}/authentication/config/{id}"

URL_ADMIN_COMPONENTS: str = "admin/realms/{realm-name}/components"
URL_ADMIN_COMPONENT: str = "admin/realms/{realm-name}/components/{component-id}"
URL_ADMIN_KEYS: str = "admin/realms/{realm-name}/keys"

URL_ADMIN_USER_FEDERATED_IDENTITIES: str = "admin/realms/{realm-name}/users/{id}/federated-identity"
URL_ADMIN_USER_FEDERATED_IDENTITY: str = (
    "admin/realms/{realm-name}/users/{id}/federated-identity/{provider}"
)

URL_ADMIN_EVENTS: str = "admin/realms/{realm-name}/events"
URL_ADMIN_EVENTS_CONFIG: str = URL_ADMIN_EVENTS + "/config"
URL_ADMIN_CLIENT_SESSION_STATS: str = "admin/realms/{realm-name}/client-session-stats"
