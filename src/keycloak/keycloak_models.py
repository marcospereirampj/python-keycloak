from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, Extra


DecisionStrategy = Enum("DecisionStrategy", ["AFFIRMATIVE", "UNANIMOUS", "CONSENSUS"])
NodeType = Enum("NodeType", ["ARRAY", "BINARY", "BOOLEAN", "MISSING", "NULL", "NUMBER", "OBJECT", "POJO", "STRING"])
PolicyEnforcementMode = Enum("PolicyEnforcementMode", ["ENFORCING", "PERMISSIVE", "DISABLED"])
Category = Enum("Category", ["INTERNAL", "ACCESS", "ID", "ADMIN", "USERINFO", "LOGOUT", "AUTHORIZATION_RESPONSE"])
Logic = Enum("Logic", ["POSITIVE", "NEGATIVE"])
Use = Enum("Use", ["SIG", "ENC"])
Policy = Enum("Policy", ["SKIP", "OVERWRITE", "FAIL"])


class KeycloakModel(BaseModel):

    def __getitem__(self, k):
        return getattr(self, k)

    def __setitem__(self, k, v):
        return setattr(self, k, v)

    def __delitem__(self, k):
        return delattr(self, k)

    def __contains__(self, k):
        return hasattr(self, k)

    def get(self, k, default=None):
        return getattr(self, k, default)

    class Config:
        validate_all = True
        validate_assignment = True
        allow_mutation = False
        extra = Extra.allow
        smart_union = True


class AccessToken(KeycloakModel):
    acr: Optional[str] = Field(None, alias="acr")
    address: Optional["AddressClaimSet"] = Field(None, alias="address")
    allowed_origins: Optional[List[str]] = Field(None, alias="allowed-origins")
    at_hash: Optional[str] = Field(None, alias="at_hash")
    auth_time: Optional[int] = Field(None, alias="auth_time")
    authorization: Optional["AccessTokenAuthorization"] = Field(None, alias="authorization")
    azp: Optional[str] = Field(None, alias="azp")
    birthdate: Optional[str] = Field(None, alias="birthdate")
    c_hash: Optional[str] = Field(None, alias="c_hash")
    category: Optional[Category] = Field(None, alias="category")
    claims_locales: Optional[str] = Field(None, alias="claims_locales")
    cnf: Optional["AccessTokenCertConf"] = Field(None, alias="cnf")
    email: Optional[str] = Field(None, alias="email")
    email_verified: Optional[bool] = Field(None, alias="email_verified")
    exp: Optional[int] = Field(None, alias="exp")
    family_name: Optional[str] = Field(None, alias="family_name")
    gender: Optional[str] = Field(None, alias="gender")
    given_name: Optional[str] = Field(None, alias="given_name")
    iat: Optional[int] = Field(None, alias="iat")
    iss: Optional[str] = Field(None, alias="iss")
    jti: Optional[str] = Field(None, alias="jti")
    locale: Optional[str] = Field(None, alias="locale")
    middle_name: Optional[str] = Field(None, alias="middle_name")
    name: Optional[str] = Field(None, alias="name")
    nbf: Optional[int] = Field(None, alias="nbf")
    nickname: Optional[str] = Field(None, alias="nickname")
    nonce: Optional[str] = Field(None, alias="nonce")
    otherClaims: Optional[Dict[Any, Any]] = Field(None, alias="otherClaims")
    phone_number: Optional[str] = Field(None, alias="phone_number")
    phone_number_verified: Optional[bool] = Field(None, alias="phone_number_verified")
    picture: Optional[str] = Field(None, alias="picture")
    preferred_username: Optional[str] = Field(None, alias="preferred_username")
    profile: Optional[str] = Field(None, alias="profile")
    realm_access: Optional["AccessTokenAccess"] = Field(None, alias="realm_access")
    s_hash: Optional[str] = Field(None, alias="s_hash")
    scope: Optional[str] = Field(None, alias="scope")
    session_state: Optional[str] = Field(None, alias="session_state")
    sid: Optional[str] = Field(None, alias="sid")
    sub: Optional[str] = Field(None, alias="sub")
    trusted_certs: Optional[List[str]] = Field(None, alias="trusted-certs")
    typ: Optional[str] = Field(None, alias="typ")
    updated_at: Optional[int] = Field(None, alias="updated_at")
    website: Optional[str] = Field(None, alias="website")
    zoneinfo: Optional[str] = Field(None, alias="zoneinfo")


class AccessTokenAccess(KeycloakModel):
    roles: Optional[List[str]] = Field(None, alias="roles")
    verify_caller: Optional[bool] = Field(None, alias="verify_caller")


class AccessTokenAuthorization(KeycloakModel):
    permissions: Optional[List["Permission"]] = Field(None, alias="permissions")


class AccessTokenCertConf(KeycloakModel):
    x5t_S256: Optional[str] = Field(None, alias="x5t#S256")


class AddressClaimSet(KeycloakModel):
    country: Optional[str] = Field(None, alias="country")
    formatted: Optional[str] = Field(None, alias="formatted")
    locality: Optional[str] = Field(None, alias="locality")
    postal_code: Optional[str] = Field(None, alias="postal_code")
    region: Optional[str] = Field(None, alias="region")
    street_address: Optional[str] = Field(None, alias="street_address")


class AuthenticationExecutionExportRepresentation(KeycloakModel):
    authenticator: Optional[str] = Field(None, alias="authenticator")
    authenticatorConfig: Optional[str] = Field(None, alias="authenticatorConfig")
    authenticatorFlow: Optional[bool] = Field(None, alias="authenticatorFlow")
    flowAlias: Optional[str] = Field(None, alias="flowAlias")
    priority: Optional[int] = Field(None, alias="priority")
    requirement: Optional[str] = Field(None, alias="requirement")
    userSetupAllowed: Optional[bool] = Field(None, alias="userSetupAllowed")


class AuthenticationExecutionInfoRepresentation(KeycloakModel):
    alias: Optional[str] = Field(None, alias="alias")
    authenticationConfig: Optional[str] = Field(None, alias="authenticationConfig")
    authenticationFlow: Optional[bool] = Field(None, alias="authenticationFlow")
    configurable: Optional[bool] = Field(None, alias="configurable")
    description: Optional[str] = Field(None, alias="description")
    displayName: Optional[str] = Field(None, alias="displayName")
    flowId: Optional[str] = Field(None, alias="flowId")
    id: Optional[str] = Field(None, alias="id")
    index: Optional[int] = Field(None, alias="index")
    level: Optional[int] = Field(None, alias="level")
    providerId: Optional[str] = Field(None, alias="providerId")
    requirement: Optional[str] = Field(None, alias="requirement")
    requirementChoices: Optional[List[str]] = Field(None, alias="requirementChoices")


class AuthenticationExecutionRepresentation(KeycloakModel):
    authenticator: Optional[str] = Field(None, alias="authenticator")
    authenticatorConfig: Optional[str] = Field(None, alias="authenticatorConfig")
    authenticatorFlow: Optional[bool] = Field(None, alias="authenticatorFlow")
    flowId: Optional[str] = Field(None, alias="flowId")
    id: Optional[str] = Field(None, alias="id")
    parentFlow: Optional[str] = Field(None, alias="parentFlow")
    priority: Optional[int] = Field(None, alias="priority")
    requirement: Optional[str] = Field(None, alias="requirement")


class AuthenticationFlowRepresentation(KeycloakModel):
    alias: Optional[str] = Field(None, alias="alias")
    authenticationExecutions: Optional[List["AuthenticationExecutionExportRepresentation"]] = Field(None, alias="authenticationExecutions")
    builtIn: Optional[bool] = Field(None, alias="builtIn")
    description: Optional[str] = Field(None, alias="description")
    id: Optional[str] = Field(None, alias="id")
    providerId: Optional[str] = Field(None, alias="providerId")
    topLevel: Optional[bool] = Field(None, alias="topLevel")


class AuthenticatorConfigInfoRepresentation(KeycloakModel):
    helpText: Optional[str] = Field(None, alias="helpText")
    name: Optional[str] = Field(None, alias="name")
    properties: Optional[List["ConfigPropertyRepresentation"]] = Field(None, alias="properties")
    providerId: Optional[str] = Field(None, alias="providerId")


class AuthenticatorConfigRepresentation(KeycloakModel):
    alias: Optional[str] = Field(None, alias="alias")
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    id: Optional[str] = Field(None, alias="id")


class CertificateRepresentation(KeycloakModel):
    certificate: Optional[str] = Field(None, alias="certificate")
    kid: Optional[str] = Field(None, alias="kid")
    privateKey: Optional[str] = Field(None, alias="privateKey")
    publicKey: Optional[str] = Field(None, alias="publicKey")


class ClientInitialAccessCreatePresentation(KeycloakModel):
    count: Optional[int] = Field(None, alias="count")
    expiration: Optional[int] = Field(None, alias="expiration")


class ClientInitialAccessPresentation(KeycloakModel):
    count: Optional[int] = Field(None, alias="count")
    expiration: Optional[int] = Field(None, alias="expiration")
    id: Optional[str] = Field(None, alias="id")
    remainingCount: Optional[int] = Field(None, alias="remainingCount")
    timestamp: Optional[int] = Field(None, alias="timestamp")
    token: Optional[str] = Field(None, alias="token")


class ClientMappingsRepresentation(KeycloakModel):
    client: Optional[str] = Field(None, alias="client")
    id: Optional[str] = Field(None, alias="id")
    mappings: Optional[List["RoleRepresentation"]] = Field(None, alias="mappings")


class ClientPoliciesRepresentation(KeycloakModel):
    policies: Optional[List["ClientPolicyRepresentation"]] = Field(None, alias="policies")


class ClientPolicyConditionRepresentation(KeycloakModel):
    condition: Optional[str] = Field(None, alias="condition")
    configuration: Optional["JsonNode"] = Field(None, alias="configuration")


class ClientPolicyExecutorRepresentation(KeycloakModel):
    configuration: Optional["JsonNode"] = Field(None, alias="configuration")
    executor: Optional[str] = Field(None, alias="executor")


class ClientPolicyRepresentation(KeycloakModel):
    conditions: Optional[List["ClientPolicyConditionRepresentation"]] = Field(None, alias="conditions")
    description: Optional[str] = Field(None, alias="description")
    enabled: Optional[bool] = Field(None, alias="enabled")
    name: Optional[str] = Field(None, alias="name")
    profiles: Optional[List[str]] = Field(None, alias="profiles")


class ClientProfileRepresentation(KeycloakModel):
    description: Optional[str] = Field(None, alias="description")
    executors: Optional[List["ClientPolicyExecutorRepresentation"]] = Field(None, alias="executors")
    name: Optional[str] = Field(None, alias="name")


class ClientProfilesRepresentation(KeycloakModel):
    globalProfiles: Optional[List["ClientProfileRepresentation"]] = Field(None, alias="globalProfiles")
    profiles: Optional[List["ClientProfileRepresentation"]] = Field(None, alias="profiles")


class ClientRepresentation(KeycloakModel):
    access: Optional[Dict[Any, Any]] = Field(None, alias="access")
    adminUrl: Optional[str] = Field(None, alias="adminUrl")
    alwaysDisplayInConsole: Optional[bool] = Field(None, alias="alwaysDisplayInConsole")
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    authenticationFlowBindingOverrides: Optional[Dict[Any, Any]] = Field(None, alias="authenticationFlowBindingOverrides")
    authorizationServicesEnabled: Optional[bool] = Field(None, alias="authorizationServicesEnabled")
    authorizationSettings: Optional["ResourceServerRepresentation"] = Field(None, alias="authorizationSettings")
    baseUrl: Optional[str] = Field(None, alias="baseUrl")
    bearerOnly: Optional[bool] = Field(None, alias="bearerOnly")
    clientAuthenticatorType: Optional[str] = Field(None, alias="clientAuthenticatorType")
    clientId: Optional[str] = Field(None, alias="clientId")
    consentRequired: Optional[bool] = Field(None, alias="consentRequired")
    defaultClientScopes: Optional[List[str]] = Field(None, alias="defaultClientScopes")
    description: Optional[str] = Field(None, alias="description")
    directAccessGrantsEnabled: Optional[bool] = Field(None, alias="directAccessGrantsEnabled")
    enabled: Optional[bool] = Field(None, alias="enabled")
    frontchannelLogout: Optional[bool] = Field(None, alias="frontchannelLogout")
    fullScopeAllowed: Optional[bool] = Field(None, alias="fullScopeAllowed")
    id: Optional[str] = Field(None, alias="id")
    implicitFlowEnabled: Optional[bool] = Field(None, alias="implicitFlowEnabled")
    name: Optional[str] = Field(None, alias="name")
    nodeReRegistrationTimeout: Optional[int] = Field(None, alias="nodeReRegistrationTimeout")
    notBefore: Optional[int] = Field(None, alias="notBefore")
    oauth2DeviceAuthorizationGrantEnabled: Optional[bool] = Field(None, alias="oauth2DeviceAuthorizationGrantEnabled")
    optionalClientScopes: Optional[List[str]] = Field(None, alias="optionalClientScopes")
    origin: Optional[str] = Field(None, alias="origin")
    protocol: Optional[str] = Field(None, alias="protocol")
    protocolMappers: Optional[List["ProtocolMapperRepresentation"]] = Field(None, alias="protocolMappers")
    publicClient: Optional[bool] = Field(None, alias="publicClient")
    redirectUris: Optional[List[str]] = Field(None, alias="redirectUris")
    registeredNodes: Optional[Dict[Any, Any]] = Field(None, alias="registeredNodes")
    registrationAccessToken: Optional[str] = Field(None, alias="registrationAccessToken")
    rootUrl: Optional[str] = Field(None, alias="rootUrl")
    secret: Optional[str] = Field(None, alias="secret")
    serviceAccountsEnabled: Optional[bool] = Field(None, alias="serviceAccountsEnabled")
    standardFlowEnabled: Optional[bool] = Field(None, alias="standardFlowEnabled")
    surrogateAuthRequired: Optional[bool] = Field(None, alias="surrogateAuthRequired")
    webOrigins: Optional[List[str]] = Field(None, alias="webOrigins")


class ClientScopeEvaluateResourceProtocolMapperEvaluationRepresentation(KeycloakModel):
    containerId: Optional[str] = Field(None, alias="containerId")
    containerName: Optional[str] = Field(None, alias="containerName")
    containerType: Optional[str] = Field(None, alias="containerType")
    mapperId: Optional[str] = Field(None, alias="mapperId")
    mapperName: Optional[str] = Field(None, alias="mapperName")
    protocolMapper: Optional[str] = Field(None, alias="protocolMapper")


class ClientScopeRepresentation(KeycloakModel):
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    description: Optional[str] = Field(None, alias="description")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    protocol: Optional[str] = Field(None, alias="protocol")
    protocolMappers: Optional[List["ProtocolMapperRepresentation"]] = Field(None, alias="protocolMappers")


class ComponentExportRepresentation(KeycloakModel):
    config: Optional["MultivaluedHashMap"] = Field(None, alias="config")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    providerId: Optional[str] = Field(None, alias="providerId")
    subComponents: Optional["MultivaluedHashMap"] = Field(None, alias="subComponents")
    subType: Optional[str] = Field(None, alias="subType")


class ComponentRepresentation(KeycloakModel):
    config: Optional["MultivaluedHashMap"] = Field(None, alias="config")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    parentId: Optional[str] = Field(None, alias="parentId")
    providerId: Optional[str] = Field(None, alias="providerId")
    providerType: Optional[str] = Field(None, alias="providerType")
    subType: Optional[str] = Field(None, alias="subType")


class ConfigPropertyRepresentation(KeycloakModel):
    defaultValue: Optional[Dict[Any, Any]] = Field(None, alias="defaultValue")
    helpText: Optional[str] = Field(None, alias="helpText")
    label: Optional[str] = Field(None, alias="label")
    name: Optional[str] = Field(None, alias="name")
    options: Optional[List[str]] = Field(None, alias="options")
    readOnly: Optional[bool] = Field(None, alias="readOnly")
    secret: Optional[bool] = Field(None, alias="secret")
    type: Optional[str] = Field(None, alias="type")


class CredentialRepresentation(KeycloakModel):
    createdDate: Optional[int] = Field(None, alias="createdDate")
    credentialData: Optional[str] = Field(None, alias="credentialData")
    id: Optional[str] = Field(None, alias="id")
    priority: Optional[int] = Field(None, alias="priority")
    secretData: Optional[str] = Field(None, alias="secretData")
    temporary: Optional[bool] = Field(None, alias="temporary")
    type: Optional[str] = Field(None, alias="type")
    userLabel: Optional[str] = Field(None, alias="userLabel")
    value: Optional[str] = Field(None, alias="value")


class FederatedIdentityRepresentation(KeycloakModel):
    identityProvider: Optional[str] = Field(None, alias="identityProvider")
    userId: Optional[str] = Field(None, alias="userId")
    userName: Optional[str] = Field(None, alias="userName")


class GlobalRequestResult(KeycloakModel):
    failedRequests: Optional[List[str]] = Field(None, alias="failedRequests")
    successRequests: Optional[List[str]] = Field(None, alias="successRequests")


class GroupRepresentation(KeycloakModel):
    access: Optional[Dict[Any, Any]] = Field(None, alias="access")
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    clientRoles: Optional[Dict[Any, Any]] = Field(None, alias="clientRoles")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    path: Optional[str] = Field(None, alias="path")
    realmRoles: Optional[List[str]] = Field(None, alias="realmRoles")
    subGroups: Optional[List["GroupRepresentation"]] = Field(None, alias="subGroups")


class IDToken(KeycloakModel):
    acr: Optional[str] = Field(None, alias="acr")
    address: Optional["AddressClaimSet"] = Field(None, alias="address")
    at_hash: Optional[str] = Field(None, alias="at_hash")
    auth_time: Optional[int] = Field(None, alias="auth_time")
    azp: Optional[str] = Field(None, alias="azp")
    birthdate: Optional[str] = Field(None, alias="birthdate")
    c_hash: Optional[str] = Field(None, alias="c_hash")
    category: Optional[Category] = Field(None, alias="category")
    claims_locales: Optional[str] = Field(None, alias="claims_locales")
    email: Optional[str] = Field(None, alias="email")
    email_verified: Optional[bool] = Field(None, alias="email_verified")
    exp: Optional[int] = Field(None, alias="exp")
    family_name: Optional[str] = Field(None, alias="family_name")
    gender: Optional[str] = Field(None, alias="gender")
    given_name: Optional[str] = Field(None, alias="given_name")
    iat: Optional[int] = Field(None, alias="iat")
    iss: Optional[str] = Field(None, alias="iss")
    jti: Optional[str] = Field(None, alias="jti")
    locale: Optional[str] = Field(None, alias="locale")
    middle_name: Optional[str] = Field(None, alias="middle_name")
    name: Optional[str] = Field(None, alias="name")
    nbf: Optional[int] = Field(None, alias="nbf")
    nickname: Optional[str] = Field(None, alias="nickname")
    nonce: Optional[str] = Field(None, alias="nonce")
    otherClaims: Optional[Dict[Any, Any]] = Field(None, alias="otherClaims")
    phone_number: Optional[str] = Field(None, alias="phone_number")
    phone_number_verified: Optional[bool] = Field(None, alias="phone_number_verified")
    picture: Optional[str] = Field(None, alias="picture")
    preferred_username: Optional[str] = Field(None, alias="preferred_username")
    profile: Optional[str] = Field(None, alias="profile")
    s_hash: Optional[str] = Field(None, alias="s_hash")
    session_state: Optional[str] = Field(None, alias="session_state")
    sid: Optional[str] = Field(None, alias="sid")
    sub: Optional[str] = Field(None, alias="sub")
    typ: Optional[str] = Field(None, alias="typ")
    updated_at: Optional[int] = Field(None, alias="updated_at")
    website: Optional[str] = Field(None, alias="website")
    zoneinfo: Optional[str] = Field(None, alias="zoneinfo")


class IdentityProviderMapperRepresentation(KeycloakModel):
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    id: Optional[str] = Field(None, alias="id")
    identityProviderAlias: Optional[str] = Field(None, alias="identityProviderAlias")
    identityProviderMapper: Optional[str] = Field(None, alias="identityProviderMapper")
    name: Optional[str] = Field(None, alias="name")


class IdentityProviderRepresentation(KeycloakModel):
    addReadTokenRoleOnCreate: Optional[bool] = Field(None, alias="addReadTokenRoleOnCreate")
    alias: Optional[str] = Field(None, alias="alias")
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    displayName: Optional[str] = Field(None, alias="displayName")
    enabled: Optional[bool] = Field(None, alias="enabled")
    firstBrokerLoginFlowAlias: Optional[str] = Field(None, alias="firstBrokerLoginFlowAlias")
    internalId: Optional[str] = Field(None, alias="internalId")
    linkOnly: Optional[bool] = Field(None, alias="linkOnly")
    postBrokerLoginFlowAlias: Optional[str] = Field(None, alias="postBrokerLoginFlowAlias")
    providerId: Optional[str] = Field(None, alias="providerId")
    storeToken: Optional[bool] = Field(None, alias="storeToken")
    trustEmail: Optional[bool] = Field(None, alias="trustEmail")


class JsonNode(KeycloakModel):
    array: Optional[bool] = Field(None, alias="array")
    bigDecimal: Optional[bool] = Field(None, alias="bigDecimal")
    bigInteger: Optional[bool] = Field(None, alias="bigInteger")
    binary: Optional[bool] = Field(None, alias="binary")
    boolean: Optional[bool] = Field(None, alias="boolean")
    containerNode: Optional[bool] = Field(None, alias="containerNode")
    double: Optional[bool] = Field(None, alias="double")
    empty: Optional[bool] = Field(None, alias="empty")
    float: Optional[bool] = Field(None, alias="float")
    floatingPointNumber: Optional[bool] = Field(None, alias="floatingPointNumber")
    int: Optional[bool] = Field(None, alias="int")
    integralNumber: Optional[bool] = Field(None, alias="integralNumber")
    long: Optional[bool] = Field(None, alias="long")
    missingNode: Optional[bool] = Field(None, alias="missingNode")
    nodeType: Optional[NodeType] = Field(None, alias="nodeType")
    null: Optional[bool] = Field(None, alias="null")
    number: Optional[bool] = Field(None, alias="number")
    object: Optional[bool] = Field(None, alias="object")
    pojo: Optional[bool] = Field(None, alias="pojo")
    short: Optional[bool] = Field(None, alias="short")
    textual: Optional[bool] = Field(None, alias="textual")
    valueNode: Optional[bool] = Field(None, alias="valueNode")


class KeyStoreConfig(KeycloakModel):
    format: Optional[str] = Field(None, alias="format")
    keyAlias: Optional[str] = Field(None, alias="keyAlias")
    keyPassword: Optional[str] = Field(None, alias="keyPassword")
    realmAlias: Optional[str] = Field(None, alias="realmAlias")
    realmCertificate: Optional[bool] = Field(None, alias="realmCertificate")
    storePassword: Optional[str] = Field(None, alias="storePassword")


class KeysMetadataRepresentation(KeycloakModel):
    active: Optional[Dict[Any, Any]] = Field(None, alias="active")
    keys: Optional[List["KeysMetadataRepresentationKeyMetadataRepresentation"]] = Field(None, alias="keys")


class KeysMetadataRepresentationKeyMetadataRepresentation(KeycloakModel):
    algorithm: Optional[str] = Field(None, alias="algorithm")
    certificate: Optional[str] = Field(None, alias="certificate")
    kid: Optional[str] = Field(None, alias="kid")
    providerId: Optional[str] = Field(None, alias="providerId")
    providerPriority: Optional[int] = Field(None, alias="providerPriority")
    publicKey: Optional[str] = Field(None, alias="publicKey")
    status: Optional[str] = Field(None, alias="status")
    type: Optional[str] = Field(None, alias="type")
    use: Optional[Use] = Field(None, alias="use")


class ManagementPermissionReference(KeycloakModel):
    enabled: Optional[bool] = Field(None, alias="enabled")
    resource: Optional[str] = Field(None, alias="resource")
    scopePermissions: Optional[Dict[Any, Any]] = Field(None, alias="scopePermissions")


class MappingsRepresentation(KeycloakModel):
    clientMappings: Optional[Dict[Any, Any]] = Field(None, alias="clientMappings")
    realmMappings: Optional[List["RoleRepresentation"]] = Field(None, alias="realmMappings")


class MemoryInfoRepresentation(KeycloakModel):
    free: Optional[int] = Field(None, alias="free")
    freeFormated: Optional[str] = Field(None, alias="freeFormated")
    freePercentage: Optional[int] = Field(None, alias="freePercentage")
    total: Optional[int] = Field(None, alias="total")
    totalFormated: Optional[str] = Field(None, alias="totalFormated")
    used: Optional[int] = Field(None, alias="used")
    usedFormated: Optional[str] = Field(None, alias="usedFormated")


class MultivaluedHashMap(KeycloakModel):
    empty: Optional[bool] = Field(None, alias="empty")
    loadFactor: Optional[float] = Field(None, alias="loadFactor")
    threshold: Optional[int] = Field(None, alias="threshold")


class PartialImportRepresentation(KeycloakModel):
    clients: Optional[List["ClientRepresentation"]] = Field(None, alias="clients")
    groups: Optional[List["GroupRepresentation"]] = Field(None, alias="groups")
    identityProviders: Optional[List["IdentityProviderRepresentation"]] = Field(None, alias="identityProviders")
    ifResourceExists: Optional[str] = Field(None, alias="ifResourceExists")
    policy: Optional[Policy] = Field(None, alias="policy")
    roles: Optional["RolesRepresentation"] = Field(None, alias="roles")
    users: Optional[List["UserRepresentation"]] = Field(None, alias="users")


class PasswordPolicyTypeRepresentation(KeycloakModel):
    configType: Optional[str] = Field(None, alias="configType")
    defaultValue: Optional[str] = Field(None, alias="defaultValue")
    displayName: Optional[str] = Field(None, alias="displayName")
    id: Optional[str] = Field(None, alias="id")
    multipleSupported: Optional[bool] = Field(None, alias="multipleSupported")


class Permission(KeycloakModel):
    claims: Optional[Dict[Any, Any]] = Field(None, alias="claims")
    rsid: Optional[str] = Field(None, alias="rsid")
    rsname: Optional[str] = Field(None, alias="rsname")
    scopes: Optional[List[str]] = Field(None, alias="scopes")


class PolicyRepresentation(KeycloakModel):
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    decisionStrategy: Optional[DecisionStrategy] = Field(None, alias="decisionStrategy")
    description: Optional[str] = Field(None, alias="description")
    id: Optional[str] = Field(None, alias="id")
    logic: Optional[Logic] = Field(None, alias="logic")
    name: Optional[str] = Field(None, alias="name")
    owner: Optional[str] = Field(None, alias="owner")
    policies: Optional[List[str]] = Field(None, alias="policies")
    resources: Optional[List[str]] = Field(None, alias="resources")
    resourcesData: Optional[List["ResourceRepresentation"]] = Field(None, alias="resourcesData")
    scopes: Optional[List[str]] = Field(None, alias="scopes")
    scopesData: Optional[List["ScopeRepresentation"]] = Field(None, alias="scopesData")
    type: Optional[str] = Field(None, alias="type")


class ProfileInfoRepresentation(KeycloakModel):
    disabledFeatures: Optional[List[str]] = Field(None, alias="disabledFeatures")
    experimentalFeatures: Optional[List[str]] = Field(None, alias="experimentalFeatures")
    name: Optional[str] = Field(None, alias="name")
    previewFeatures: Optional[List[str]] = Field(None, alias="previewFeatures")


class ProtocolMapperRepresentation(KeycloakModel):
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    protocol: Optional[str] = Field(None, alias="protocol")
    protocolMapper: Optional[str] = Field(None, alias="protocolMapper")


class ProviderRepresentation(KeycloakModel):
    operationalInfo: Optional[Dict[Any, Any]] = Field(None, alias="operationalInfo")
    order: Optional[int] = Field(None, alias="order")


class RealmEventsConfigRepresentation(KeycloakModel):
    adminEventsDetailsEnabled: Optional[bool] = Field(None, alias="adminEventsDetailsEnabled")
    adminEventsEnabled: Optional[bool] = Field(None, alias="adminEventsEnabled")
    enabledEventTypes: Optional[List[str]] = Field(None, alias="enabledEventTypes")
    eventsEnabled: Optional[bool] = Field(None, alias="eventsEnabled")
    eventsExpiration: Optional[int] = Field(None, alias="eventsExpiration")
    eventsListeners: Optional[List[str]] = Field(None, alias="eventsListeners")


class RealmRepresentation(KeycloakModel):
    accessCodeLifespan: Optional[int] = Field(None, alias="accessCodeLifespan")
    accessCodeLifespanLogin: Optional[int] = Field(None, alias="accessCodeLifespanLogin")
    accessCodeLifespanUserAction: Optional[int] = Field(None, alias="accessCodeLifespanUserAction")
    accessTokenLifespan: Optional[int] = Field(None, alias="accessTokenLifespan")
    accessTokenLifespanForImplicitFlow: Optional[int] = Field(None, alias="accessTokenLifespanForImplicitFlow")
    accountTheme: Optional[str] = Field(None, alias="accountTheme")
    actionTokenGeneratedByAdminLifespan: Optional[int] = Field(None, alias="actionTokenGeneratedByAdminLifespan")
    actionTokenGeneratedByUserLifespan: Optional[int] = Field(None, alias="actionTokenGeneratedByUserLifespan")
    adminEventsDetailsEnabled: Optional[bool] = Field(None, alias="adminEventsDetailsEnabled")
    adminEventsEnabled: Optional[bool] = Field(None, alias="adminEventsEnabled")
    adminTheme: Optional[str] = Field(None, alias="adminTheme")
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    authenticationFlows: Optional[List["AuthenticationFlowRepresentation"]] = Field(None, alias="authenticationFlows")
    authenticatorConfig: Optional[List["AuthenticatorConfigRepresentation"]] = Field(None, alias="authenticatorConfig")
    browserFlow: Optional[str] = Field(None, alias="browserFlow")
    browserSecurityHeaders: Optional[Dict[Any, Any]] = Field(None, alias="browserSecurityHeaders")
    bruteForceProtected: Optional[bool] = Field(None, alias="bruteForceProtected")
    clientAuthenticationFlow: Optional[str] = Field(None, alias="clientAuthenticationFlow")
    clientOfflineSessionIdleTimeout: Optional[int] = Field(None, alias="clientOfflineSessionIdleTimeout")
    clientOfflineSessionMaxLifespan: Optional[int] = Field(None, alias="clientOfflineSessionMaxLifespan")
    clientPolicies: Optional["JsonNode"] = Field(None, alias="clientPolicies")
    clientProfiles: Optional["JsonNode"] = Field(None, alias="clientProfiles")
    clientScopeMappings: Optional[Dict[Any, Any]] = Field(None, alias="clientScopeMappings")
    clientScopes: Optional[List["ClientScopeRepresentation"]] = Field(None, alias="clientScopes")
    clientSessionIdleTimeout: Optional[int] = Field(None, alias="clientSessionIdleTimeout")
    clientSessionMaxLifespan: Optional[int] = Field(None, alias="clientSessionMaxLifespan")
    clients: Optional[List["ClientRepresentation"]] = Field(None, alias="clients")
    components: Optional["MultivaluedHashMap"] = Field(None, alias="components")
    defaultDefaultClientScopes: Optional[List[str]] = Field(None, alias="defaultDefaultClientScopes")
    defaultGroups: Optional[List[str]] = Field(None, alias="defaultGroups")
    defaultLocale: Optional[str] = Field(None, alias="defaultLocale")
    defaultOptionalClientScopes: Optional[List[str]] = Field(None, alias="defaultOptionalClientScopes")
    defaultRole: Optional["RoleRepresentation"] = Field(None, alias="defaultRole")
    defaultSignatureAlgorithm: Optional[str] = Field(None, alias="defaultSignatureAlgorithm")
    directGrantFlow: Optional[str] = Field(None, alias="directGrantFlow")
    displayName: Optional[str] = Field(None, alias="displayName")
    displayNameHtml: Optional[str] = Field(None, alias="displayNameHtml")
    dockerAuthenticationFlow: Optional[str] = Field(None, alias="dockerAuthenticationFlow")
    duplicateEmailsAllowed: Optional[bool] = Field(None, alias="duplicateEmailsAllowed")
    editUsernameAllowed: Optional[bool] = Field(None, alias="editUsernameAllowed")
    emailTheme: Optional[str] = Field(None, alias="emailTheme")
    enabled: Optional[bool] = Field(None, alias="enabled")
    enabledEventTypes: Optional[List[str]] = Field(None, alias="enabledEventTypes")
    eventsEnabled: Optional[bool] = Field(None, alias="eventsEnabled")
    eventsExpiration: Optional[int] = Field(None, alias="eventsExpiration")
    eventsListeners: Optional[List[str]] = Field(None, alias="eventsListeners")
    failureFactor: Optional[int] = Field(None, alias="failureFactor")
    federatedUsers: Optional[List["UserRepresentation"]] = Field(None, alias="federatedUsers")
    groups: Optional[List["GroupRepresentation"]] = Field(None, alias="groups")
    id: Optional[str] = Field(None, alias="id")
    identityProviderMappers: Optional[List["IdentityProviderMapperRepresentation"]] = Field(None, alias="identityProviderMappers")
    identityProviders: Optional[List["IdentityProviderRepresentation"]] = Field(None, alias="identityProviders")
    internationalizationEnabled: Optional[bool] = Field(None, alias="internationalizationEnabled")
    keycloakVersion: Optional[str] = Field(None, alias="keycloakVersion")
    loginTheme: Optional[str] = Field(None, alias="loginTheme")
    loginWithEmailAllowed: Optional[bool] = Field(None, alias="loginWithEmailAllowed")
    maxDeltaTimeSeconds: Optional[int] = Field(None, alias="maxDeltaTimeSeconds")
    maxFailureWaitSeconds: Optional[int] = Field(None, alias="maxFailureWaitSeconds")
    minimumQuickLoginWaitSeconds: Optional[int] = Field(None, alias="minimumQuickLoginWaitSeconds")
    notBefore: Optional[int] = Field(None, alias="notBefore")
    oAuth2DeviceCodeLifespan: Optional[int] = Field(None, alias="oAuth2DeviceCodeLifespan")
    oAuth2DevicePollingInterval: Optional[int] = Field(None, alias="oAuth2DevicePollingInterval")
    oauth2DeviceCodeLifespan: Optional[int] = Field(None, alias="oauth2DeviceCodeLifespan")
    oauth2DevicePollingInterval: Optional[int] = Field(None, alias="oauth2DevicePollingInterval")
    offlineSessionIdleTimeout: Optional[int] = Field(None, alias="offlineSessionIdleTimeout")
    offlineSessionMaxLifespan: Optional[int] = Field(None, alias="offlineSessionMaxLifespan")
    offlineSessionMaxLifespanEnabled: Optional[bool] = Field(None, alias="offlineSessionMaxLifespanEnabled")
    otpPolicyAlgorithm: Optional[str] = Field(None, alias="otpPolicyAlgorithm")
    otpPolicyDigits: Optional[int] = Field(None, alias="otpPolicyDigits")
    otpPolicyInitialCounter: Optional[int] = Field(None, alias="otpPolicyInitialCounter")
    otpPolicyLookAheadWindow: Optional[int] = Field(None, alias="otpPolicyLookAheadWindow")
    otpPolicyPeriod: Optional[int] = Field(None, alias="otpPolicyPeriod")
    otpPolicyType: Optional[str] = Field(None, alias="otpPolicyType")
    otpSupportedApplications: Optional[List[str]] = Field(None, alias="otpSupportedApplications")
    passwordPolicy: Optional[str] = Field(None, alias="passwordPolicy")
    permanentLockout: Optional[bool] = Field(None, alias="permanentLockout")
    protocolMappers: Optional[List["ProtocolMapperRepresentation"]] = Field(None, alias="protocolMappers")
    quickLoginCheckMilliSeconds: Optional[int] = Field(None, alias="quickLoginCheckMilliSeconds")
    realm: Optional[str] = Field(None, alias="realm")
    refreshTokenMaxReuse: Optional[int] = Field(None, alias="refreshTokenMaxReuse")
    registrationAllowed: Optional[bool] = Field(None, alias="registrationAllowed")
    registrationEmailAsUsername: Optional[bool] = Field(None, alias="registrationEmailAsUsername")
    registrationFlow: Optional[str] = Field(None, alias="registrationFlow")
    rememberMe: Optional[bool] = Field(None, alias="rememberMe")
    requiredActions: Optional[List["RequiredActionProviderRepresentation"]] = Field(None, alias="requiredActions")
    resetCredentialsFlow: Optional[str] = Field(None, alias="resetCredentialsFlow")
    resetPasswordAllowed: Optional[bool] = Field(None, alias="resetPasswordAllowed")
    revokeRefreshToken: Optional[bool] = Field(None, alias="revokeRefreshToken")
    roles: Optional["RolesRepresentation"] = Field(None, alias="roles")
    scopeMappings: Optional[List["ScopeMappingRepresentation"]] = Field(None, alias="scopeMappings")
    smtpServer: Optional[Dict[Any, Any]] = Field(None, alias="smtpServer")
    sslRequired: Optional[str] = Field(None, alias="sslRequired")
    ssoSessionIdleTimeout: Optional[int] = Field(None, alias="ssoSessionIdleTimeout")
    ssoSessionIdleTimeoutRememberMe: Optional[int] = Field(None, alias="ssoSessionIdleTimeoutRememberMe")
    ssoSessionMaxLifespan: Optional[int] = Field(None, alias="ssoSessionMaxLifespan")
    ssoSessionMaxLifespanRememberMe: Optional[int] = Field(None, alias="ssoSessionMaxLifespanRememberMe")
    supportedLocales: Optional[List[str]] = Field(None, alias="supportedLocales")
    userFederationMappers: Optional[List["UserFederationMapperRepresentation"]] = Field(None, alias="userFederationMappers")
    userFederationProviders: Optional[List["UserFederationProviderRepresentation"]] = Field(None, alias="userFederationProviders")
    userManagedAccessAllowed: Optional[bool] = Field(None, alias="userManagedAccessAllowed")
    users: Optional[List["UserRepresentation"]] = Field(None, alias="users")
    verifyEmail: Optional[bool] = Field(None, alias="verifyEmail")
    waitIncrementSeconds: Optional[int] = Field(None, alias="waitIncrementSeconds")
    webAuthnPolicyAcceptableAaguids: Optional[List[str]] = Field(None, alias="webAuthnPolicyAcceptableAaguids")
    webAuthnPolicyAttestationConveyancePreference: Optional[str] = Field(None, alias="webAuthnPolicyAttestationConveyancePreference")
    webAuthnPolicyAuthenticatorAttachment: Optional[str] = Field(None, alias="webAuthnPolicyAuthenticatorAttachment")
    webAuthnPolicyAvoidSameAuthenticatorRegister: Optional[bool] = Field(None, alias="webAuthnPolicyAvoidSameAuthenticatorRegister")
    webAuthnPolicyCreateTimeout: Optional[int] = Field(None, alias="webAuthnPolicyCreateTimeout")
    webAuthnPolicyPasswordlessAcceptableAaguids: Optional[List[str]] = Field(None, alias="webAuthnPolicyPasswordlessAcceptableAaguids")
    webAuthnPolicyPasswordlessAttestationConveyancePreference: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessAttestationConveyancePreference")
    webAuthnPolicyPasswordlessAuthenticatorAttachment: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessAuthenticatorAttachment")
    webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: Optional[bool] = Field(None, alias="webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister")
    webAuthnPolicyPasswordlessCreateTimeout: Optional[int] = Field(None, alias="webAuthnPolicyPasswordlessCreateTimeout")
    webAuthnPolicyPasswordlessRequireResidentKey: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessRequireResidentKey")
    webAuthnPolicyPasswordlessRpEntityName: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessRpEntityName")
    webAuthnPolicyPasswordlessRpId: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessRpId")
    webAuthnPolicyPasswordlessSignatureAlgorithms: Optional[List[str]] = Field(None, alias="webAuthnPolicyPasswordlessSignatureAlgorithms")
    webAuthnPolicyPasswordlessUserVerificationRequirement: Optional[str] = Field(None, alias="webAuthnPolicyPasswordlessUserVerificationRequirement")
    webAuthnPolicyRequireResidentKey: Optional[str] = Field(None, alias="webAuthnPolicyRequireResidentKey")
    webAuthnPolicyRpEntityName: Optional[str] = Field(None, alias="webAuthnPolicyRpEntityName")
    webAuthnPolicyRpId: Optional[str] = Field(None, alias="webAuthnPolicyRpId")
    webAuthnPolicySignatureAlgorithms: Optional[List[str]] = Field(None, alias="webAuthnPolicySignatureAlgorithms")
    webAuthnPolicyUserVerificationRequirement: Optional[str] = Field(None, alias="webAuthnPolicyUserVerificationRequirement")


class RequiredActionProviderRepresentation(KeycloakModel):
    alias: Optional[str] = Field(None, alias="alias")
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    defaultAction: Optional[bool] = Field(None, alias="defaultAction")
    enabled: Optional[bool] = Field(None, alias="enabled")
    name: Optional[str] = Field(None, alias="name")
    priority: Optional[int] = Field(None, alias="priority")
    providerId: Optional[str] = Field(None, alias="providerId")


class ResourceRepresentation(KeycloakModel):
    id: str = Field(None, alias="id")
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    displayName: Optional[str] = Field(None, alias="displayName")
    icon_uri: Optional[str] = Field(None, alias="icon_uri")
    name: Optional[str] = Field(None, alias="name")
    ownerManagedAccess: Optional[bool] = Field(None, alias="ownerManagedAccess")
    scopes: Optional[List["ScopeRepresentation"]] = Field(None, alias="scopes")
    type: Optional[str] = Field(None, alias="type")
    uris: Optional[List[str]] = Field(None, alias="uris")


class ResourceServerRepresentation(KeycloakModel):
    allowRemoteResourceManagement: Optional[bool] = Field(None, alias="allowRemoteResourceManagement")
    clientId: Optional[str] = Field(None, alias="clientId")
    decisionStrategy: Optional[DecisionStrategy] = Field(None, alias="decisionStrategy")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    policies: Optional[List["PolicyRepresentation"]] = Field(None, alias="policies")
    policyEnforcementMode: Optional[PolicyEnforcementMode] = Field(None, alias="policyEnforcementMode")
    resources: Optional[List["ResourceRepresentation"]] = Field(None, alias="resources")
    scopes: Optional[List["ScopeRepresentation"]] = Field(None, alias="scopes")


class RoleRepresentation(KeycloakModel):
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    clientRole: Optional[bool] = Field(None, alias="clientRole")
    composite: Optional[bool] = Field(None, alias="composite")
    composites: Optional["RoleRepresentationComposites"] = Field(None, alias="composites")
    containerId: Optional[str] = Field(None, alias="containerId")
    description: Optional[str] = Field(None, alias="description")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")


class RoleRepresentationComposites(KeycloakModel):
    client: Optional[Dict[Any, Any]] = Field(None, alias="client")
    realm: Optional[List[str]] = Field(None, alias="realm")


class RolesRepresentation(KeycloakModel):
    client: Optional[Dict[Any, Any]] = Field(None, alias="client")
    realm: Optional[List["RoleRepresentation"]] = Field(None, alias="realm")


class ScopeMappingRepresentation(KeycloakModel):
    client: Optional[str] = Field(None, alias="client")
    clientScope: Optional[str] = Field(None, alias="clientScope")
    roles: Optional[List[str]] = Field(None, alias="roles")
    self: Optional[str] = Field(None, alias="self")


class ScopeRepresentation(KeycloakModel):
    displayName: Optional[str] = Field(None, alias="displayName")
    iconUri: Optional[str] = Field(None, alias="iconUri")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")
    policies: Optional[List["PolicyRepresentation"]] = Field(None, alias="policies")
    resources: Optional[List["ResourceRepresentation"]] = Field(None, alias="resources")


class ServerInfoRepresentation(KeycloakModel):
    builtinProtocolMappers: Optional[Dict[Any, Any]] = Field(None, alias="builtinProtocolMappers")
    clientImporters: Optional[List[Dict[Any, Any]]] = Field(None, alias="clientImporters")
    clientInstallations: Optional[Dict[Any, Any]] = Field(None, alias="clientInstallations")
    componentTypes: Optional[Dict[Any, Any]] = Field(None, alias="componentTypes")
    enums: Optional[Dict[Any, Any]] = Field(None, alias="enums")
    identityProviders: Optional[List[Dict[Any, Any]]] = Field(None, alias="identityProviders")
    memoryInfo: Optional["MemoryInfoRepresentation"] = Field(None, alias="memoryInfo")
    passwordPolicies: Optional[List["PasswordPolicyTypeRepresentation"]] = Field(None, alias="passwordPolicies")
    profileInfo: Optional["ProfileInfoRepresentation"] = Field(None, alias="profileInfo")
    protocolMapperTypes: Optional[Dict[Any, Any]] = Field(None, alias="protocolMapperTypes")
    providers: Optional[Dict[Any, Any]] = Field(None, alias="providers")
    socialProviders: Optional[List[Dict[Any, Any]]] = Field(None, alias="socialProviders")
    systemInfo: Optional["SystemInfoRepresentation"] = Field(None, alias="systemInfo")
    themes: Optional[Dict[Any, Any]] = Field(None, alias="themes")


class SpiInfoRepresentation(KeycloakModel):
    internal: Optional[bool] = Field(None, alias="internal")
    providers: Optional[Dict[Any, Any]] = Field(None, alias="providers")


class SynchronizationResult(KeycloakModel):
    added: Optional[int] = Field(None, alias="added")
    failed: Optional[int] = Field(None, alias="failed")
    ignored: Optional[bool] = Field(None, alias="ignored")
    removed: Optional[int] = Field(None, alias="removed")
    status: Optional[str] = Field(None, alias="status")
    updated: Optional[int] = Field(None, alias="updated")


class SystemInfoRepresentation(KeycloakModel):
    fileEncoding: Optional[str] = Field(None, alias="fileEncoding")
    javaHome: Optional[str] = Field(None, alias="javaHome")
    javaRuntime: Optional[str] = Field(None, alias="javaRuntime")
    javaVendor: Optional[str] = Field(None, alias="javaVendor")
    javaVersion: Optional[str] = Field(None, alias="javaVersion")
    javaVm: Optional[str] = Field(None, alias="javaVm")
    javaVmVersion: Optional[str] = Field(None, alias="javaVmVersion")
    osArchitecture: Optional[str] = Field(None, alias="osArchitecture")
    osName: Optional[str] = Field(None, alias="osName")
    osVersion: Optional[str] = Field(None, alias="osVersion")
    serverTime: Optional[str] = Field(None, alias="serverTime")
    uptime: Optional[str] = Field(None, alias="uptime")
    uptimeMillis: Optional[int] = Field(None, alias="uptimeMillis")
    userDir: Optional[str] = Field(None, alias="userDir")
    userLocale: Optional[str] = Field(None, alias="userLocale")
    userName: Optional[str] = Field(None, alias="userName")
    userTimezone: Optional[str] = Field(None, alias="userTimezone")
    version: Optional[str] = Field(None, alias="version")


class TestLdapConnectionRepresentation(KeycloakModel):
    action: Optional[str] = Field(None, alias="action")
    authType: Optional[str] = Field(None, alias="authType")
    bindCredential: Optional[str] = Field(None, alias="bindCredential")
    bindDn: Optional[str] = Field(None, alias="bindDn")
    componentId: Optional[str] = Field(None, alias="componentId")
    connectionTimeout: Optional[str] = Field(None, alias="connectionTimeout")
    connectionUrl: Optional[str] = Field(None, alias="connectionUrl")
    startTls: Optional[str] = Field(None, alias="startTls")
    useTruststoreSpi: Optional[str] = Field(None, alias="useTruststoreSpi")


class UserConsentRepresentation(KeycloakModel):
    clientId: Optional[str] = Field(None, alias="clientId")
    createdDate: Optional[int] = Field(None, alias="createdDate")
    grantedClientScopes: Optional[List[str]] = Field(None, alias="grantedClientScopes")
    lastUpdatedDate: Optional[int] = Field(None, alias="lastUpdatedDate")


class UserFederationMapperRepresentation(KeycloakModel):
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    federationMapperType: Optional[str] = Field(None, alias="federationMapperType")
    federationProviderDisplayName: Optional[str] = Field(None, alias="federationProviderDisplayName")
    id: Optional[str] = Field(None, alias="id")
    name: Optional[str] = Field(None, alias="name")


class UserFederationProviderRepresentation(KeycloakModel):
    changedSyncPeriod: Optional[int] = Field(None, alias="changedSyncPeriod")
    config: Optional[Dict[Any, Any]] = Field(None, alias="config")
    displayName: Optional[str] = Field(None, alias="displayName")
    fullSyncPeriod: Optional[int] = Field(None, alias="fullSyncPeriod")
    id: Optional[str] = Field(None, alias="id")
    lastSync: Optional[int] = Field(None, alias="lastSync")
    priority: Optional[int] = Field(None, alias="priority")
    providerName: Optional[str] = Field(None, alias="providerName")


class UserRepresentation(KeycloakModel):
    access: Optional[Dict[Any, Any]] = Field(None, alias="access")
    attributes: Optional[Dict[Any, Any]] = Field(None, alias="attributes")
    clientConsents: Optional[List["UserConsentRepresentation"]] = Field(None, alias="clientConsents")
    clientRoles: Optional[Dict[Any, Any]] = Field(None, alias="clientRoles")
    createdTimestamp: Optional[int] = Field(None, alias="createdTimestamp")
    credentials: Optional[List["CredentialRepresentation"]] = Field(None, alias="credentials")
    disableableCredentialTypes: Optional[List[str]] = Field(None, alias="disableableCredentialTypes")
    email: Optional[str] = Field(None, alias="email")
    emailVerified: Optional[bool] = Field(None, alias="emailVerified")
    enabled: Optional[bool] = Field(None, alias="enabled")
    federatedIdentities: Optional[List["FederatedIdentityRepresentation"]] = Field(None, alias="federatedIdentities")
    federationLink: Optional[str] = Field(None, alias="federationLink")
    firstName: Optional[str] = Field(None, alias="firstName")
    groups: Optional[List[str]] = Field(None, alias="groups")
    id: Optional[str] = Field(None, alias="id")
    lastName: Optional[str] = Field(None, alias="lastName")
    notBefore: Optional[int] = Field(None, alias="notBefore")
    origin: Optional[str] = Field(None, alias="origin")
    realmRoles: Optional[List[str]] = Field(None, alias="realmRoles")
    requiredActions: Optional[List[str]] = Field(None, alias="requiredActions")
    self: Optional[str] = Field(None, alias="self")
    serviceAccountClientId: Optional[str] = Field(None, alias="serviceAccountClientId")
    username: Optional[str] = Field(None, alias="username")
