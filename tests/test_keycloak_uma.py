"""Test module for KeycloakUMA."""

import re

import pytest

from keycloak import KeycloakAdmin, KeycloakOpenIDConnection, KeycloakUMA
from keycloak.exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
)
from keycloak.uma_permissions import UMAPermission


def test_keycloak_uma_init(oid_connection_with_authz: KeycloakOpenIDConnection):
    """Test KeycloakUMA's init method.

    :param oid_connection_with_authz: Keycloak OpenID connection manager with preconfigured authz
    :type oid_connection_with_authz: KeycloakOpenIDConnection
    """
    connection = oid_connection_with_authz
    uma = KeycloakUMA(connection=connection)

    assert isinstance(uma.connection, KeycloakOpenIDConnection)
    # should initially be empty
    assert uma._well_known is None
    assert uma.uma_well_known
    # should be cached after first reference
    assert uma._well_known is not None


def test_uma_well_known(uma: KeycloakUMA):
    """Test the well_known method.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    res = uma.uma_well_known
    assert res is not None
    assert res != dict()
    for key in ["resource_registration_endpoint"]:
        assert key in res


def test_uma_resource_sets(uma: KeycloakUMA):
    """Test resource sets.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    # Check that only the default resource is present
    resource_sets = uma.resource_set_list()
    resource_set_list = list(resource_sets)
    assert len(resource_set_list) == 1, resource_set_list
    assert resource_set_list[0]["name"] == "Default Resource", resource_set_list[0]["name"]

    # Test query for resource sets
    resource_set_list_ids = uma.resource_set_list_ids()
    assert len(resource_set_list_ids) == 1

    resource_set_list_ids2 = uma.resource_set_list_ids(name="Default")
    assert resource_set_list_ids2 == resource_set_list_ids

    resource_set_list_ids2 = uma.resource_set_list_ids(name="Default Resource")
    assert resource_set_list_ids2 == resource_set_list_ids

    resource_set_list_ids = uma.resource_set_list_ids(name="Default", exact_name=True)
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(first=1)
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(scope="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(owner="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(resource_type="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(name="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(uri="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = uma.resource_set_list_ids(maximum=0)
    assert len(resource_set_list_ids) == 0

    # Test create resource set
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
    }
    created_resource = uma.resource_set_create(resource_to_create)
    assert created_resource
    assert created_resource["_id"], created_resource
    assert set(resource_to_create).issubset(set(created_resource)), created_resource

    # Test create the same resource set
    with pytest.raises(KeycloakPostError) as err:
        uma.resource_set_create(resource_to_create)
    assert err.match(
        re.escape(
            '409: b\'{"error":"invalid_request","error_description":'
            '"Resource with name [mytest] already exists."}\''
        )
    )

    # Test get resource set
    latest_resource = uma.resource_set_read(created_resource["_id"])
    assert latest_resource["name"] == created_resource["name"]

    # Test update resource set
    latest_resource["name"] = "New Resource Name"
    res = uma.resource_set_update(created_resource["_id"], latest_resource)
    assert res == dict(), res
    updated_resource = uma.resource_set_read(created_resource["_id"])
    assert updated_resource["name"] == "New Resource Name"

    # Test update resource set fail
    with pytest.raises(KeycloakPutError) as err:
        uma.resource_set_update(resource_id=created_resource["_id"], payload={"wrong": "payload"})
    assert err.match('400: b\'{"error":"Unrecognized field')

    # Test delete resource set
    res = uma.resource_set_delete(resource_id=created_resource["_id"])
    assert res == dict(), res
    with pytest.raises(KeycloakGetError) as err:
        uma.resource_set_read(created_resource["_id"])
    err.match("404: b''")

    # Test delete fail
    with pytest.raises(KeycloakDeleteError) as err:
        uma.resource_set_delete(resource_id=created_resource["_id"])
    assert err.match("404: b''")


def test_uma_policy(uma: KeycloakUMA, admin: KeycloakAdmin):
    """Test policies.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    # Create some required test data
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    created_resource = uma.resource_set_create(resource_to_create)
    group_id = admin.create_group({"name": "UMAPolicyGroup"})
    role_id = admin.create_realm_role(payload={"name": "roleUMAPolicy"})
    other_client_id = admin.create_client({"name": "UMAOtherClient"})
    client = admin.get_client(other_client_id)

    resource_id = created_resource["_id"]

    # Create a role policy
    policy_to_create = {
        "name": "TestPolicyRole",
        "description": "Test resource policy description",
        "scopes": ["test:read", "test:write"],
        "roles": ["roleUMAPolicy"],
    }
    policy = uma.policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    # Create a client policy
    policy_to_create = {
        "name": "TestPolicyClient",
        "description": "Test resource policy description",
        "scopes": ["test:read"],
        "clients": [client["clientId"]],
    }
    policy = uma.policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    policy_to_create = {
        "name": "TestPolicyGroup",
        "description": "Test resource policy description",
        "scopes": ["test:read"],
        "groups": ["/UMAPolicyGroup"],
    }
    policy = uma.policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    policies = uma.policy_query()
    assert len(policies) == 3

    policies = uma.policy_query(name="TestPolicyGroup")
    assert len(policies) == 1

    policy_id = policy["id"]
    uma.policy_delete(policy_id)
    with pytest.raises(KeycloakDeleteError) as err:
        uma.policy_delete(policy_id)
    assert err.match(
        '404: b\'{"error":"invalid_request","error_description":"Policy with .* does not exist"}\''
    )

    policies = uma.policy_query()
    assert len(policies) == 2

    policy = policies[0]
    uma.policy_update(policy_id=policy["id"], payload=policy)

    policies = uma.policy_query()
    assert len(policies) == 2

    policies = uma.policy_query(name="Invalid")
    assert len(policies) == 0
    policies = uma.policy_query(scope="Invalid")
    assert len(policies) == 0
    policies = uma.policy_query(resource="Invalid")
    assert len(policies) == 0
    policies = uma.policy_query(first=3)
    assert len(policies) == 0
    policies = uma.policy_query(maximum=0)
    assert len(policies) == 0

    policies = uma.policy_query(name=policy["name"])
    assert len(policies) == 1
    policies = uma.policy_query(scope=policy["scopes"][0])
    assert len(policies) == 2
    policies = uma.policy_query(resource=resource_id)
    assert len(policies) == 2

    uma.resource_set_delete(resource_id)
    admin.delete_client(other_client_id)
    admin.delete_realm_role(role_id)
    admin.delete_group(group_id)


def test_uma_access(uma: KeycloakUMA):
    """Test permission access checks.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    resource_to_create = {
        "name": "mytest",
        "scopes": ["read", "write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    resource = uma.resource_set_create(resource_to_create)

    policy_to_create = {
        "name": "TestPolicy",
        "description": "Test resource policy description",
        "scopes": [resource_to_create["scopes"][0]],
        "clients": [uma.connection.client_id],
    }
    uma.policy_resource_create(resource_id=resource["_id"], payload=policy_to_create)

    token = uma.connection.token
    permissions = list()
    assert uma.permissions_check(token["access_token"], permissions)

    permissions.append(UMAPermission(resource=resource_to_create["name"]))
    assert uma.permissions_check(token["access_token"], permissions)

    permissions.append(UMAPermission(resource="not valid"))
    assert not uma.permissions_check(token["access_token"], permissions)
    uma.resource_set_delete(resource["_id"])


def test_uma_permission_ticket(uma: KeycloakUMA):
    """Test permission ticket generation.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    resource_to_create = {
        "name": "mytest",
        "scopes": ["read", "write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    resource = uma.resource_set_create(resource_to_create)

    policy_to_create = {
        "name": "TestPolicy",
        "description": "Test resource policy description",
        "scopes": [resource_to_create["scopes"][0]],
        "clients": [uma.connection.client_id],
    }
    uma.policy_resource_create(resource_id=resource["_id"], payload=policy_to_create)
    permissions = (
        UMAPermission(resource=resource_to_create["name"], scope=resource_to_create["scopes"][0]),
    )
    response = uma.permission_ticket_create(permissions)

    rpt = uma.connection.keycloak_openid.token(
        grant_type="urn:ietf:params:oauth:grant-type:uma-ticket", ticket=response["ticket"]
    )
    assert rpt
    assert "access_token" in rpt

    permissions = (UMAPermission(resource="invalid"),)
    with pytest.raises(KeycloakPostError):
        uma.permission_ticket_create(permissions)

    uma.resource_set_delete(resource["_id"])

#async function start

@pytest.mark.asyncio
async def test_a_uma_well_known(uma: KeycloakUMA):
    """Test the well_known method.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    res = uma.uma_well_known
    assert res is not None
    assert res != dict()
    for key in ["resource_registration_endpoint"]:
        assert key in res

@pytest.mark.asyncio
async def test_a_uma_resource_sets(uma: KeycloakUMA):
    """Test resource sets.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    # Check that only the default resource is present
    resource_sets = await uma.a_resource_set_list()
    resource_set_list = list(resource_sets)
    assert len(resource_set_list) == 1, resource_set_list
    assert resource_set_list[0]["name"] == "Default Resource", resource_set_list[0]["name"]

    # Test query for resource sets
    resource_set_list_ids = await uma.a_resource_set_list_ids()
    assert len(resource_set_list_ids) == 1

    resource_set_list_ids2 = await uma.a_resource_set_list_ids(name="Default")
    assert resource_set_list_ids2 == resource_set_list_ids

    resource_set_list_ids2 = await uma.a_resource_set_list_ids(name="Default Resource")
    assert resource_set_list_ids2 == resource_set_list_ids

    resource_set_list_ids = await uma.a_resource_set_list_ids(name="Default", exact_name=True)
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(first=1)
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(scope="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(owner="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(resource_type="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(name="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(uri="Invalid")
    assert len(resource_set_list_ids) == 0

    resource_set_list_ids = await uma.a_resource_set_list_ids(maximum=0)
    assert len(resource_set_list_ids) == 0

    # Test create resource set
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
    }
    created_resource = await uma.a_resource_set_create(resource_to_create)
    assert created_resource
    assert created_resource["_id"], created_resource
    assert set(resource_to_create).issubset(set(created_resource)), created_resource

    # Test create the same resource set
    with pytest.raises(KeycloakPostError) as err:
        await uma.a_resource_set_create(resource_to_create)
    assert err.match(
        re.escape(
            '409: b\'{"error":"invalid_request","error_description":'
            '"Resource with name [mytest] already exists."}\''
        )
    )

    # Test get resource set
    latest_resource = await uma.a_resource_set_read(created_resource["_id"])
    assert latest_resource["name"] == created_resource["name"]

    # Test update resource set
    latest_resource["name"] = "New Resource Name"
    res = await uma.a_resource_set_update(created_resource["_id"], latest_resource)
    assert res == dict(), res
    updated_resource = await uma.a_resource_set_read(created_resource["_id"])
    assert updated_resource["name"] == "New Resource Name"

    # Test update resource set fail
    with pytest.raises(KeycloakPutError) as err:
        uma.resource_set_update(resource_id=created_resource["_id"], payload={"wrong": "payload"})
    assert err.match('400: b\'{"error":"Unrecognized field')

    # Test delete resource set
    res = await uma.a_resource_set_delete(resource_id=created_resource["_id"])
    assert res == dict(), res
    with pytest.raises(KeycloakGetError) as err:
        await uma.a_resource_set_read(created_resource["_id"])
    err.match("404: b''")

    # Test delete fail
    with pytest.raises(KeycloakDeleteError) as err:
        await uma.a_resource_set_delete(resource_id=created_resource["_id"])
    assert err.match("404: b''")

@pytest.mark.asyncio
async def test_a_uma_policy(uma: KeycloakUMA, admin: KeycloakAdmin):
    """Test policies.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    # Create some required test data
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    created_resource = await uma.a_resource_set_create(resource_to_create)
    group_id = admin.create_group({"name": "UMAPolicyGroup"})
    role_id = admin.create_realm_role(payload={"name": "roleUMAPolicy"})
    other_client_id = admin.create_client({"name": "UMAOtherClient"})
    client = admin.get_client(other_client_id)

    resource_id = created_resource["_id"]

    # Create a role policy
    policy_to_create = {
        "name": "TestPolicyRole",
        "description": "Test resource policy description",
        "scopes": ["test:read", "test:write"],
        "roles": ["roleUMAPolicy"],
    }
    policy = await uma.a_policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    # Create a client policy
    policy_to_create = {
        "name": "TestPolicyClient",
        "description": "Test resource policy description",
        "scopes": ["test:read"],
        "clients": [client["clientId"]],
    }
    policy = await uma.a_policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    policy_to_create = {
        "name": "TestPolicyGroup",
        "description": "Test resource policy description",
        "scopes": ["test:read"],
        "groups": ["/UMAPolicyGroup"],
    }
    policy = await uma.a_policy_resource_create(resource_id=resource_id, payload=policy_to_create)
    assert policy

    policies = await uma.a_policy_query()
    assert len(policies) == 3

    policies = await uma.a_policy_query(name="TestPolicyGroup")
    assert len(policies) == 1

    policy_id = policy["id"]
    await uma.a_policy_delete(policy_id)
    with pytest.raises(KeycloakDeleteError) as err:
        await uma.a_policy_delete(policy_id)
    assert err.match(
        '404: b\'{"error":"invalid_request","error_description":"Policy with .* does not exist"}\''
    )

    policies = await uma.a_policy_query()
    assert len(policies) == 2

    policy = policies[0]
    await uma.a_policy_update(policy_id=policy["id"], payload=policy)

    policies = await uma.a_policy_query()
    assert len(policies) == 2

    policies = await uma.a_policy_query(name="Invalid")
    assert len(policies) == 0
    policies = await uma.a_policy_query(scope="Invalid")
    assert len(policies) == 0
    policies = await uma.a_policy_query(resource="Invalid")
    assert len(policies) == 0
    policies = await uma.a_policy_query(first=3)
    assert len(policies) == 0
    policies = await uma.a_policy_query(maximum=0)
    assert len(policies) == 0

    policies = await uma.a_policy_query(name=policy["name"])
    assert len(policies) == 1
    policies = await uma.a_policy_query(scope=policy["scopes"][0])
    assert len(policies) == 2
    policies = await uma.a_policy_query(resource=resource_id)
    assert len(policies) == 2

    uma.a_resource_set_delete(resource_id)
    admin.delete_client(other_client_id)
    admin.delete_realm_role(role_id)
    admin.delete_group(group_id)

@pytest.mark.asyncio
async def test_a_uma_access(uma: KeycloakUMA):
    """Test permission access checks.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    resource_to_create = {
        "name": "mytest",
        "scopes": ["read", "write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    resource = await uma.a_resource_set_create(resource_to_create)

    policy_to_create = {
        "name": "TestPolicy",
        "description": "Test resource policy description",
        "scopes": [resource_to_create["scopes"][0]],
        "clients": [uma.connection.client_id],
    }
    await uma.a_policy_resource_create(resource_id=resource["_id"], payload=policy_to_create)

    token = uma.connection.token
    permissions = list()
    assert await uma.a_permissions_check(token["access_token"], permissions)

    permissions.append(UMAPermission(resource=resource_to_create["name"]))
    assert await uma.a_permissions_check(token["access_token"], permissions)

    permissions.append(UMAPermission(resource="not valid"))
    assert not await uma.a_permissions_check(token["access_token"], permissions)
    uma.resource_set_delete(resource["_id"])

@pytest.mark.asyncio
async def test_a_uma_permission_ticket(uma: KeycloakUMA):
    """Test permission ticket generation.

    :param uma: Keycloak UMA client
    :type uma: KeycloakUMA
    """
    resource_to_create = {
        "name": "mytest",
        "scopes": ["read", "write"],
        "type": "urn:test",
        "ownerManagedAccess": True,
    }
    resource = await uma.a_resource_set_create(resource_to_create)

    policy_to_create = {
        "name": "TestPolicy",
        "description": "Test resource policy description",
        "scopes": [resource_to_create["scopes"][0]],
        "clients": [uma.connection.client_id],
    }
    await uma.a_policy_resource_create(resource_id=resource["_id"], payload=policy_to_create)
    permissions = (
        UMAPermission(resource=resource_to_create["name"], scope=resource_to_create["scopes"][0]),
    )
    response = await uma.a_permission_ticket_create(permissions)

    rpt = await uma.connection.keycloak_openid.a_token(
        grant_type="urn:ietf:params:oauth:grant-type:uma-ticket", ticket=response["ticket"]
    )
    assert rpt
    assert "access_token" in rpt

    permissions = (UMAPermission(resource="invalid"),)
    with pytest.raises(KeycloakPostError):
        uma.permission_ticket_create(permissions)

    await uma.a_resource_set_delete(resource["_id"])
