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

from httmock import urlmatch, response, HTTMock, all_requests

from ..connection import ConnectionManager

try:
    import unittest
except ImportError:
    import unittest2 as unittest


class TestConnection(unittest.TestCase):

    def setUp(self):
        self._conn = ConnectionManager(
            base_url="http://localhost/",
            headers={},
            timeout=60)

    @all_requests
    def response_content_success(self, url, request):
        headers = {'content-type': 'application/json'}
        content = b'response_ok'
        return response(200, content, headers, None, 5, request)

    def test_raw_get(self):
        with HTTMock(self.response_content_success):
            resp = self._conn.raw_get("/known_path")
        self.assertEqual(resp.content, b'response_ok')
        self.assertEqual(resp.status_code, 200)

    def test_raw_post(self):
        @urlmatch(path="/known_path", method="post")
        def response_post_success(url, request):
            headers = {'content-type': 'application/json'}
            content = 'response'.encode("utf-8")
            return response(201, content, headers, None, 5, request)

        with HTTMock(response_post_success):
            resp = self._conn.raw_post("/known_path",
                                       {'field': 'value'})
        self.assertEqual(resp.content, b'response')
        self.assertEqual(resp.status_code, 201)

    def test_raw_put(self):
        @urlmatch(netloc="localhost", path="/known_path", method="put")
        def response_put_success(url, request):
            headers = {'content-type': 'application/json'}
            content = 'response'.encode("utf-8")
            return response(200, content, headers, None, 5, request)

        with HTTMock(response_put_success):
            resp = self._conn.raw_put("/known_path",
                                      {'field': 'value'})
        self.assertEqual(resp.content, b'response')
        self.assertEqual(resp.status_code, 200)

    def test_raw_get_fail(self):
        @urlmatch(netloc="localhost", path="/known_path", method="get")
        def response_get_fail(url, request):
            headers = {'content-type': 'application/json'}
            content = "404 page not found".encode("utf-8")
            return response(404, content, headers, None, 5, request)

        with HTTMock(response_get_fail):
            resp = self._conn.raw_get("/known_path")

        self.assertEqual(resp.content, b"404 page not found")
        self.assertEqual(resp.status_code, 404)

    def test_raw_post_fail(self):
        @urlmatch(netloc="localhost", path="/known_path", method="post")
        def response_post_fail(url, request):
            headers = {'content-type': 'application/json'}
            content = str(["Start can't be blank"]).encode("utf-8")
            return response(404, content, headers, None, 5, request)

        with HTTMock(response_post_fail):
            resp = self._conn.raw_post("/known_path",
                                       {'field': 'value'})
        self.assertEqual(resp.content, str(["Start can't be blank"]).encode("utf-8"))
        self.assertEqual(resp.status_code, 404)

    def test_raw_put_fail(self):
        @urlmatch(netloc="localhost", path="/known_path", method="put")
        def response_put_fail(url, request):
            headers = {'content-type': 'application/json'}
            content = str(["Start can't be blank"]).encode("utf-8")
            return response(404, content, headers, None, 5, request)

        with HTTMock(response_put_fail):
            resp = self._conn.raw_put("/known_path",
                                      {'field': 'value'})
        self.assertEqual(resp.content, str(["Start can't be blank"]).encode("utf-8"))
        self.assertEqual(resp.status_code, 404)

    def test_add_param_headers(self):
        self._conn.add_param_headers("test", "value")
        self.assertEqual(self._conn.headers,
                         {"test": "value"})

    def test_del_param_headers(self):
        self._conn.add_param_headers("test", "value")
        self._conn.del_param_headers("test")
        self.assertEqual(self._conn.headers, {})

    def test_clean_param_headers(self):
        self._conn.add_param_headers("test", "value")
        self.assertEqual(self._conn.headers,
                         {"test": "value"})
        self._conn.clean_headers()
        self.assertEqual(self._conn.headers, {})

    def test_exist_param_headers(self):
        self._conn.add_param_headers("test", "value")
        self.assertTrue(self._conn.exist_param_headers("test"))
        self.assertFalse(self._conn.exist_param_headers("test_no"))

    def test_get_param_headers(self):
        self._conn.add_param_headers("test", "value")
        self.assertTrue(self._conn.exist_param_headers("test"))
        self.assertFalse(self._conn.exist_param_headers("test_no"))

    def test_get_headers(self):
        self._conn.add_param_headers("test", "value")
        self.assertEqual(self._conn.headers,
                         {"test": "value"})
