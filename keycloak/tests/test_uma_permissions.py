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
from ..uma_permissions import *
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
    def test_call_permission(self):
        test = namedtuple("test",
                          ["name", "permission", "args", "kwargs", "result", "error"])
        tests = [
            test("Resource(Scope)", Resource("Resource1"),
                 [Scope("Scope1")], {},
                 "Resource1#Scope1", Success),
            test("Scope(Resource)", Scope("Scope1"),
                 [Resource("Resource1")], {},
                 "Resource1#Scope1", Success),

            test("Resource(scope=str)", Resource("Resource1"),
                 [], {"scope": "Scope1"},
                 "Resource1#Scope1", Success),
            test("Scope(resource=str)", Scope("Scope1"),
                 [], {"resource": "Resource1"},
                 "Resource1#Scope1", Success),

            test("Resource(str)", Resource("Resource1"),
                 ["Scope1"], {},
                 "", PermissionDefinitionError),
        ]

        for case in tests:
            with self.subTest(case.name):
                msg = f'in case "{case.name}"'
                try:
                    if not case.error is Success:
                        with self.assertRaises(case.error, msg=msg):
                            case.permission(*case.args, **case.kwargs)
                    else:
                        self.assertEqual(
                            case.permission(*case.args, **case.kwargs),
                            case.result, msg=msg)
                except AssertionError:
                    raise
                except Exception as e:
                    self.fail(
                        f'unexpected exception "{e}": {msg}')
