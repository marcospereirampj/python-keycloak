"""Test module for KeycloakUMA."""
import re

import pytest

from keycloak.exceptions import (
    KeycloakDeleteError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
)
from keycloak.keycloak_openid import KeycloakOpenIDConnectionManager
from keycloak.keycloak_uma import KeycloakUMA


def test_keycloak_uma_init(oid_connection_with_authz: KeycloakOpenIDConnectionManager):
    """Test KeycloakUMA's init method.

    :param oid_connection_with_authz: Keycloak OpenID connection manager with preconfigured authz
    :type oid_connection_with_authz: KeycloakOpenIDConnectionManager
    """
    connection = oid_connection_with_authz
    uma = KeycloakUMA(connection=connection)

    assert isinstance(uma.connection, KeycloakOpenIDConnectionManager)
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
