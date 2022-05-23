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
import re

import pytest

from keycloak.exceptions import KeycloakPermissionFormatError, PermissionDefinitionError
from keycloak.uma_permissions import Resource, Scope, build_permission_param


def test_resource_with_scope_obj():
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert r(s) == "Resource1#Scope1"


def test_scope_with_resource_obj():
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert s(r) == "Resource1#Scope1"


def test_resource_scope_str():
    r = Resource("Resource1")
    s = "Scope1"
    assert r(scope=s) == "Resource1#Scope1"


def test_scope_resource_str():
    r = "Resource1"
    s = Scope("Scope1")
    assert s(resource=r) == "Resource1#Scope1"


def test_resource_scope_list():
    r = Resource("Resource1")
    s = ["Scope1"]
    with pytest.raises(PermissionDefinitionError) as err:
        r(s)
    assert err.match(re.escape("can't determine if '['Scope1']' is a resource or scope"))


def test_build_permission_none():
    assert build_permission_param(None) == set()


def test_build_permission_empty_str():
    assert build_permission_param("") == set()


def test_build_permission_empty_list():
    assert build_permission_param([]) == set()


def test_build_permission_empty_tuple():
    assert build_permission_param(()) == set()


def test_build_permission_empty_set():
    assert build_permission_param(set()) == set()


def test_build_permission_empty_dict():
    assert build_permission_param({}) == set()


def test_build_permission_str():
    assert build_permission_param("resource1") == {"resource1"}


def test_build_permission_list_str():
    assert build_permission_param(["res1#scope1", "res1#scope2"]) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_str():
    assert build_permission_param(("res1#scope1", "res1#scope2")) == {"res1#scope1", "res1#scope2"}


def test_build_permission_set_str():
    assert build_permission_param({"res1#scope1", "res1#scope2"}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_str():
    assert build_permission_param({"res1": "scope1"}) == {"res1#scope1"}


def test_build_permission_tuple_dict_str_list_str():
    assert build_permission_param({"res1": ["scope1", "scope2"]}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_list_str2():
    assert build_permission_param(
        {"res1": ["scope1", "scope2"], "res2": ["scope2", "scope3"]}
    ) == {"res1#scope1", "res1#scope2", "res2#scope2", "res2#scope3"}


def test_build_permission_uma():
    assert build_permission_param(Resource("res1")(Scope("scope1"))) == {"res1#scope1"}


def test_build_permission_uma_list():
    assert build_permission_param(
        [Resource("res1")(Scope("scope1")), Resource("res1")(Scope("scope2"))]
    ) == {"res1#scope1", "res1#scope2"}


def test_build_permission_misbuilt_dict_str_list_list_str():
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": [["scope1", "scope2"]]})
    assert err.match(re.escape("misbuilt permission {'res1': [['scope1', 'scope2']]}"))


def test_build_permission_misbuilt_list_list_str():
    with pytest.raises(KeycloakPermissionFormatError) as err:
        print(build_permission_param([["scope1", "scope2"]]))
    assert err.match(re.escape("misbuilt permission [['scope1', 'scope2']]"))


def test_build_permission_misbuilt_list_set_str():
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param([{"scope1", "scope2"}])
    assert err.match("misbuilt permission.*")


def test_build_permission_misbuilt_set_set_str():
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param([{"scope1"}])
    assert err.match(re.escape("misbuilt permission [{'scope1'}]"))


def test_build_permission_misbuilt_dict_non_iterable():
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": 5})
    assert err.match(re.escape("misbuilt permission {'res1': 5}"))
