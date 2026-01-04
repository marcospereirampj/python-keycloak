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

"""Connection manager module."""

from __future__ import annotations

try:
    from urllib.parse import urljoin
except ImportError:  # pragma: no cover
    from urlparse import urljoin  # pyright: ignore[reportMissingImports]

from typing import Any

import httpx
import requests
from httpx import Response as AsyncResponse
from requests import Response
from requests.adapters import HTTPAdapter
from requests_toolbelt import MultipartEncoder

from .exceptions import KeycloakConnectionError


class ConnectionManager:
    """
    Represents a simple server connection.

    :param base_url: The server URL.
    :type base_url: str
    :param headers: The header parameters of the requests to the server.
    :type headers: dict
    :param timeout: Timeout to use for requests to the server.
    :type timeout: int
    :param verify: Boolean value to enable or disable certificate validation or a string
        containing a path to a CA bundle to use
    :type verify: Union[bool,str]
    :param proxies: The proxies servers requests is sent by.
    :type proxies: dict
    :param cert: An SSL certificate used by the requested host to authenticate the client.
        Either a path to an SSL certificate file, or two-tuple of
        (certificate file, key file).
    :type cert: Union[str,Tuple[str,str]]
    :param max_retries: The total number of times to retry HTTP requests.
    :type max_retries: int
    :param pool_maxsize: The maximum number of connections to save in the pool.
    :type pool_maxsize: int
    """

    def __init__(
        self,
        base_url: str,
        headers: dict | None = None,
        timeout: int | None = 60,
        verify: bool | str = True,
        proxies: dict | None = None,
        cert: str | tuple | None = None,
        max_retries: int = 1,
        pool_maxsize: int | None = None,
    ) -> None:
        """
        Init method.

        :param base_url: The server URL.
        :type base_url: str
        :param headers: The header parameters of the requests to the server.
        :type headers: dict
        :param timeout: Timeout to use for requests to the server.
        :type timeout: int
        :param verify: Boolean value to enable or disable certificate validation or a string
            containing a path to a CA bundle to use
        :type verify: Union[bool,str]
        :param proxies: The proxies servers requests is sent by.
        :type proxies: dict
        :param cert: An SSL certificate used by the requested host to authenticate the client.
            Either a path to an SSL certificate file, or two-tuple of
            (certificate file, key file).
        :type cert: Union[str,Tuple[str,str]]
        :param max_retries: The total number of times to retry HTTP requests.
        :type max_retries: int
        :param pool_maxsize: The maximum number of connections to save in the pool.
        :type pool_maxsize: int
        """
        self.base_url = base_url
        self.headers = headers
        self.timeout = timeout
        self.verify = verify
        self.proxies = proxies
        self.cert = cert
        self.max_retries = max_retries
        self.pool_maxsize = pool_maxsize
        self._s = requests.Session()
        self._s.auth = lambda x: x  # don't let requests add auth headers

        # retry once to reset connection with Keycloak after  tomcat's ConnectionTimeout
        # see https://github.com/marcospereirampj/python-keycloak/issues/36
        for protocol in ("https://", "http://"):
            adapter_kwargs = {"max_retries": max_retries}
            if pool_maxsize is not None:
                adapter_kwargs["pool_maxsize"] = pool_maxsize
            adapter = HTTPAdapter(**adapter_kwargs)  # pyright: ignore[reportArgumentType]
            # adds POST to retry whitelist
            allowed_methods = (
                set(adapter.max_retries.allowed_methods)
                if adapter.max_retries.allowed_methods
                else set()
            )
            allowed_methods.add("POST")
            adapter.max_retries.allowed_methods = frozenset(allowed_methods)

            self._s.mount(protocol, adapter)

        if proxies:
            self._s.proxies.update(proxies)

        self.async_s = httpx.AsyncClient(
            verify=verify,
            mounts=proxies,
            cert=cert,
            limits=httpx.Limits(
                max_connections=100 if pool_maxsize is None else pool_maxsize,
                max_keepalive_connections=20,
            ),
        )
        self.async_s.auth = None  # pyright: ignore[reportAttributeAccessIssue]

    async def aclose(self) -> None:
        """Close the async connection on delete."""
        if hasattr(self, "_s"):
            await self.async_s.aclose()

    def __del__(self) -> None:
        """Del method."""
        if hasattr(self, "_s"):
            self._s.close()

    @property
    def base_url(self) -> str | None:
        """
        Return base url in use for requests to the server.

        :returns: Base URL
        :rtype: str
        """
        return self._base_url

    @base_url.setter
    def base_url(self, value: str | None) -> None:
        self._base_url = value

    @property
    def timeout(self) -> int | None:
        """
        Return timeout in use for request to the server.

        :returns: Timeout
        :rtype: int
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int | None) -> None:
        self._timeout = value

    @property
    def verify(self) -> bool | str:
        """
        Return verify in use for request to the server.

        :returns: Verify indicator
        :rtype: bool
        """
        return self._verify

    @verify.setter
    def verify(self, value: bool | str) -> None:
        self._verify = value

    @property
    def proxies(self) -> dict | None:
        """
        Return proxies in use for request to the server.

        :returns: Proxies
        :rtype: dict | None
        """
        return self._proxies

    @proxies.setter
    def proxies(self, value: dict | None) -> None:
        self._proxies = value

    @property
    def cert(self) -> str | tuple | None:
        """
        Return client certificates in use for request to the server.

        :returns: Client certificate
        :rtype: Union[str,Tuple[str,str]]
        """
        return self._cert

    @cert.setter
    def cert(self, value: str | tuple | None) -> None:
        self._cert = value

    @property
    def max_retries(self) -> int:
        """
        Return maximum number of retries in use for requests to the server.

        :returns: Maximum number of retries
        :rtype: int
        """
        return self._max_retries

    @max_retries.setter
    def max_retries(self, value: int) -> None:
        self._max_retries = value

    @property
    def pool_maxsize(self) -> int | None:
        """
        Return the maximum number of connections to save in the pool.

        :returns: Pool maxsize
        :rtype: int or None
        """
        return self._pool_maxsize

    @pool_maxsize.setter
    def pool_maxsize(self, value: int | None) -> None:
        self._pool_maxsize = value

    @property
    def headers(self) -> dict | None:
        """
        Return header request to the server.

        :returns: Request headers
        :rtype: dict
        """
        return self._headers

    @headers.setter
    def headers(self, value: dict | None) -> None:
        self._headers = value or {}

    def param_headers(self, key: str) -> str | None:
        """
        Return a specific header parameter.

        :param key: Header parameters key.
        :type key: str
        :returns: If the header parameters exist, return its value.
        :rtype: str
        """
        return (self.headers or {}).get(key)

    def clean_headers(self) -> None:
        """Clear header parameters."""
        self.headers = {}

    def exist_param_headers(self, key: str) -> bool:
        """
        Check if the parameter exists in the header.

        :param key: Header parameters key.
        :type key: str
        :returns: If the header parameters exist, return True.
        :rtype: bool
        """
        return self.param_headers(key) is not None

    def add_param_headers(self, key: str, value: str) -> None:
        """
        Add a single parameter inside the header.

        :param key: Header parameters key.
        :type key: str
        :param value: Value to be added.
        :type value: str
        """
        if self.headers is None:
            self.headers = {}

        self.headers[key] = value

    def del_param_headers(self, key: str) -> None:
        """
        Remove a specific parameter.

        :param key: Key of the header parameters.
        :type key: str
        """
        if self.headers is None:
            return

        self.headers.pop(key, None)

    def raw_get(self, path: str, **kwargs: Any) -> Response:  # noqa: ANN401
        """
        Submit get request to the path.

        :param path: Path for request.
        :type path: str
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform GET call with base_url missing."
            raise AttributeError(msg)
        try:
            return self._s.get(
                urljoin(self.base_url, path),
                params=kwargs,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
                cert=self.cert,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    def raw_post(self, path: str, data: dict | str | MultipartEncoder, **kwargs: Any) -> Response:  # noqa: ANN401
        """
        Submit post request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | str | MultipartEncoder
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform POST call with base_url missing."
            raise AttributeError(msg)
        try:
            return self._s.post(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
                cert=self.cert,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    def raw_put(self, path: str, data: dict | str | MultipartEncoder, **kwargs: Any) -> Response:  # noqa: ANN401
        """
        Submit put request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | str | MultipartEncoder
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform PUT call with base_url missing."
            raise AttributeError(msg)

        try:
            return self._s.put(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
                cert=self.cert,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    def raw_delete(self, path: str, data: dict | None = None, **kwargs: Any) -> Response:  # noqa: ANN401
        """
        Submit delete request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | None
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform DELETE call with base_url missing."
            raise AttributeError(msg)

        try:
            return self._s.delete(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data or {},
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
                cert=self.cert,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    async def a_raw_get(self, path: str, **kwargs: Any) -> AsyncResponse:  # noqa: ANN401
        """
        Submit get request to the path.

        :param path: Path for request.
        :type path: str
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform GET call with base_url missing."
            raise AttributeError(msg)

        try:
            return await self.async_s.get(
                urljoin(self.base_url, path),
                params=self._filter_query_params(kwargs),
                headers=self.headers,
                timeout=self.timeout,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    async def a_raw_post(
        self,
        path: str,
        data: dict | str | MultipartEncoder,
        **kwargs: Any,  # noqa: ANN401
    ) -> AsyncResponse:
        """
        Submit post request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | str | MultipartEncoder
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform POST call with base_url missing."
            raise AttributeError(msg)

        try:
            return await self.async_s.request(
                method="POST",
                url=urljoin(self.base_url, path),
                params=self._filter_query_params(kwargs),
                **self._prepare_httpx_request_content(data),
                headers=self.headers,
                timeout=self.timeout,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    async def a_raw_put(
        self,
        path: str,
        data: dict | str | MultipartEncoder,
        **kwargs: Any,  # noqa: ANN401
    ) -> AsyncResponse:
        """
        Submit put request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | str | MultipartEncoder
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform PUT call with base_url missing."
            raise AttributeError(msg)

        try:
            return await self.async_s.put(
                urljoin(self.base_url, path),
                params=self._filter_query_params(kwargs),
                **self._prepare_httpx_request_content(data),
                headers=self.headers,
                timeout=self.timeout,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    async def a_raw_delete(
        self,
        path: str,
        data: dict | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> AsyncResponse:
        """
        Submit delete request to the path.

        :param path: Path for request.
        :type path: str
        :param data: Payload for request.
        :type data: dict | None
        :param kwargs: Additional arguments
        :type kwargs: dict
        :returns: Response the request.
        :rtype: Response
        :raises KeycloakConnectionError: HttpError Can't connect to server.
        """
        if self.base_url is None:
            msg = "Unable to perform DELETE call with base_url missing."
            raise AttributeError(msg)

        try:
            return await self.async_s.request(
                method="DELETE",
                url=urljoin(self.base_url, path),
                **self._prepare_httpx_request_content(data or {}),
                params=self._filter_query_params(kwargs),
                headers=self.headers,
                timeout=self.timeout,
            )
        except Exception as e:
            msg = "Can't connect to server"
            raise KeycloakConnectionError(msg) from e

    @staticmethod
    def _prepare_httpx_request_content(data: dict | str | None | MultipartEncoder) -> dict:
        """
        Create the correct request content kwarg to `httpx.AsyncClient.request()`.

        See https://www.python-httpx.org/compatibility/#request-content

        :param data: the request content
        :type data: dict | str | None | MultipartEncoder
        :returns: A dict mapping the correct kwarg to the request content
        :rtype: dict
        """
        if isinstance(data, MultipartEncoder):
            return {"content": data.to_string()}

        if isinstance(data, str):
            # Note: this could also accept bytes, Iterable[bytes], or AsyncIterable[bytes]
            return {"content": data}

        return {"data": data}

    @staticmethod
    def _filter_query_params(query_params: dict) -> dict:
        """
        Explicitly filter query params with None values for compatibility.

        Httpx and requests differ in the way they handle query params with the value None,
        requests does not include params with the value None while httpx includes them as-is.

        :param query_params: the query params
        :type query_params: dict
        :returns: the filtered query params
        :rtype: dict
        """
        return {k: v for k, v in query_params.items() if v is not None}
