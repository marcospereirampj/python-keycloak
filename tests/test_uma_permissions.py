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

"""Test uma permissions."""

import re

import pytest

from keycloak.exceptions import KeycloakPermissionFormatError, PermissionDefinitionError
from keycloak.uma_permissions import (
    AuthStatus,
    Resource,
    Scope,
    UMAPermission,
    build_permission_param,
)


def test_uma_permission_obj():
    """Test generic UMA permission."""
    with pytest.raises(PermissionDefinitionError):
        UMAPermission(permission="bad")

    p1 = UMAPermission(permission=Resource("Resource"))
    assert p1.resource == "Resource"
    assert p1.scope == ""
    assert repr(p1) == "Resource"
    assert str(p1) == "Resource"

    p2 = UMAPermission(permission=Scope("Scope"))
    assert p2.resource == ""
    assert p2.scope == "Scope"
    assert repr(p2) == "#Scope"
    assert str(p2) == "#Scope"
    assert {p1, p1} != {p2, p2}


def test_resource_with_scope_obj():
    """Test resource with scope."""
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert r(s) == "Resource1#Scope1"


def test_scope_with_resource_obj():
    """Test scope with resource."""
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert s(r) == "Resource1#Scope1"


def test_resource_scope_str():
    """Test resource scope as string."""
    r = Resource("Resource1")
    s = "Scope1"
    assert r(scope=s) == "Resource1#Scope1"


def test_scope_resource_str():
    """Test scope resource as string."""
    r = "Resource1"
    s = Scope("Scope1")
    assert s(resource=r) == "Resource1#Scope1"


def test_resource_scope_list():
    """Test resource scope as list."""
    r = Resource("Resource1")
    s = ["Scope1"]
    with pytest.raises(PermissionDefinitionError) as err:
        r(s)
    assert err.match(re.escape("can't determine if '['Scope1']' is a resource or scope"))


def test_build_permission_none():
    """Test build permission param with None."""
    assert build_permission_param(None) == set()


def test_build_permission_empty_str():
    """Test build permission param with an empty string."""
    assert build_permission_param("") == set()


def test_build_permission_empty_list():
    """Test build permission param with an empty list."""
    assert build_permission_param([]) == set()


def test_build_permission_empty_tuple():
    """Test build permission param with an empty tuple."""
    assert build_permission_param(()) == set()


def test_build_permission_empty_set():
    """Test build permission param with an empty set."""
    assert build_permission_param(set()) == set()


def test_build_permission_empty_dict():
    """Test build permission param with an empty dict."""
    assert build_permission_param({}) == set()


def test_build_permission_str():
    """Test build permission param as string."""
    assert build_permission_param("resource1") == {"resource1"}


def test_build_permission_list_str():
    """Test build permission param with list of strings."""
    assert build_permission_param(["res1#scope1", "res1#scope2"]) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_str():
    """Test build permission param with tuple of strings."""
    assert build_permission_param(("res1#scope1", "res1#scope2")) == {"res1#scope1", "res1#scope2"}


def test_build_permission_set_str():
    """Test build permission param with set of strings."""
    assert build_permission_param({"res1#scope1", "res1#scope2"}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_str():
    """Test build permission param with dictionary."""
    assert build_permission_param({"res1": "scope1"}) == {"res1#scope1"}


def test_build_permission_tuple_dict_str_list_str():
    """Test build permission param with dictionary of list."""
    assert build_permission_param({"res1": ["scope1", "scope2"]}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_list_str2():
    """Test build permission param with mutliple-keyed dictionary."""
    assert build_permission_param(
        {"res1": ["scope1", "scope2"], "res2": ["scope2", "scope3"]}
    ) == {"res1#scope1", "res1#scope2", "res2#scope2", "res2#scope3"}


def test_build_permission_uma():
    """Test build permission param with UMA."""
    assert build_permission_param(Resource("res1")(Scope("scope1"))) == {"res1#scope1"}


def test_build_permission_uma_list():
    """Test build permission param with list of UMAs."""
    assert build_permission_param(
        [Resource("res1")(Scope("scope1")), Resource("res1")(Scope("scope2"))]
    ) == {"res1#scope1", "res1#scope2"}


def test_build_permission_misbuilt_dict_str_list_list_str():
    """Test bad build of permission param from dictionary."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": [["scope1", "scope2"]]})
    assert err.match(re.escape("misbuilt permission {'res1': [['scope1', 'scope2']]}"))


def test_build_permission_misbuilt_list_list_str():
    """Test bad build of permission param from list."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        print(build_permission_param([["scope1", "scope2"]]))
    assert err.match(re.escape("misbuilt permission [['scope1', 'scope2']]"))


def test_build_permission_misbuilt_list_set_str():
    """Test bad build of permission param from set."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param([{"scope1", "scope2"}])
    assert err.match("misbuilt permission.*")


def test_build_permission_misbuilt_set_set_str():
    """Test bad build of permission param from list of set."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param([{"scope1"}])
    assert err.match(re.escape("misbuilt permission [{'scope1'}]"))


def test_build_permission_misbuilt_dict_non_iterable():
    """Test bad build of permission param from non-iterable."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": 5})
    assert err.match(re.escape("misbuilt permission {'res1': 5}"))


def test_auth_status_bool():
    """Test bool method of AuthStatus."""
    assert not bool(AuthStatus(is_logged_in=True, is_authorized=False, missing_permissions=""))
    assert bool(AuthStatus(is_logged_in=True, is_authorized=True, missing_permissions=""))


def test_build_permission_without_scopes():
    """Test build permission param with scopes."""
    assert build_permission_param(permissions={"Resource": None}) == {"Resource"}
