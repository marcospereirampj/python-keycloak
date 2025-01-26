"""Test authorization module."""

import pytest

from keycloak.authorization import Permission, Policy, Role
from keycloak.exceptions import KeycloakAuthorizationConfigError


def test_authorization_objects() -> None:
    """Test authorization objects."""
    # Test permission
    p = Permission(name="test", type="test", logic="test", decision_strategy="test")
    assert p.name == "test"
    assert p.type == "test"
    assert p.logic == "test"
    assert p.decision_strategy == "test"
    p.resources = ["test"]
    assert p.resources == ["test"]
    p.scopes = ["test"]
    assert p.scopes == ["test"]

    # Test policy
    p = Policy(name="test", type="test", logic="test", decision_strategy="test")
    assert p.name == "test"
    assert p.type == "test"
    assert p.logic == "test"
    assert p.decision_strategy == "test"
    p.roles = ["test"]
    assert p.roles == ["test"]
    p.permissions = ["test"]
    assert p.permissions == ["test"]
    p.add_permission(permission="test2")
    assert p.permissions == ["test", "test2"]
    with pytest.raises(KeycloakAuthorizationConfigError):
        p.add_role(role="test2")

    # Test role
    r = Role(name="test")
    assert r.name == "test"
    assert not r.required
    assert r.get_name() == "test"
    assert r == r  # noqa: PLR0124
    assert r == "test"

    with pytest.raises(NotImplementedError) as err:
        assert r == 1

    assert str(err.value) == "Cannot compare Role with <class 'int'>"
