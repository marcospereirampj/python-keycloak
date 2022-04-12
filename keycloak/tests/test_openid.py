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
from ..keycloak_openid import *
from ..exceptions import *
try:
    import unittest
except ImportError:
    import unittest2 as unittest

from collections import namedtuple


class Success(Exception):
    """Used as stand-in for an actual exception for tests that are meant to succeed.
    This exception should never be raised."""


class TestOpenID(unittest.TestCase):
    def test_build_permission_param(self):
        test = namedtuple("test",
                          ["name", "permission", "result", "error"])
        tests = [
            test("None", None, set(), Success),
            test("empty str", "", set(), Success),
            test("empty list", [], set(), Success),
            test("empty tuple", (), set(), Success),
            test("empty set", set(), set(), Success),
            test("empty dict", {}, set(), Success),

            test("str", "resource1", {"resource1"}, Success),

            test("list[str]", ["res1#scope1", "res1#scope2"],
                 {"res1#scope1", "res1#scope2"}, Success),

            test("tuple[str]", ("res1#scope1", "res1#scope2"),
                 {"res1#scope1", "res1#scope2"}, Success),

            test("set[str]", {"res1#scope1", "res1#scope2"},
                 {"res1#scope1", "res1#scope2"}, Success),

            test("dict[str,str]", {"res1": "scope1"},
                 {"res1#scope1"}, Success),
            test("dict[str,list[str]]", {"res1": ["scope1", "scope2"]},
                 {"res1#scope1", "res1#scope2"}, Success),
            test("dict[str,list[str]] 2", {"res1": ["scope1", "scope2"], "res2": ["scope2", "scope3"]},
                 {"res1#scope1", "res1#scope2", "res2#scope2", "res2#scope3"}, Success),

            test("misbuilt: dict[str,list[list[str]]]", {
                "res1": [["scope1", "scope2"]]}, None, KeycloakPermissionFormatError),
            test("misbuilt: list[list[str]]",
                 [["scope1", "scope2"]], None, KeycloakPermissionFormatError),
            test("misbuilt: list[set[str]]",
                 [{"scope1", "scope2"}], None, KeycloakPermissionFormatError),
            test("misbuilt: set[set[str]]",
                 [{"scope1"}], None, KeycloakPermissionFormatError),
        ]

        for case in tests:
            with self.subTest(case.name):
                msg = f'in case "{case.name}"'
                try:
                    if not case.error is Success:
                        with self.assertRaises(case.error, msg=msg):
                            build_permission_param(case.permission)
                    else:
                        self.assertEqual(
                            build_permission_param(case.permission),
                            case.result, msg=msg)
                except AssertionError:
                    raise
                except Exception as e:
                    self.fail(
                        f'unexpected exception "{e}": {msg}')
