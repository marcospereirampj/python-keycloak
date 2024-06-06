"""Connection test module."""

from inspect import signature

import pytest

from keycloak.connection import ConnectionManager
from keycloak.exceptions import KeycloakConnectionError


def test_connection_proxy():
    """Test proxies of connection manager."""
    cm = ConnectionManager(
        base_url="http://test.test", proxies={"http://test.test": "http://localhost:8080"}
    )
    assert cm._s.proxies == {"http://test.test": "http://localhost:8080"}


def test_headers():
    """Test headers manipulation."""
    cm = ConnectionManager(base_url="http://test.test", headers={"H": "A"})
    assert cm.param_headers(key="H") == "A"
    assert cm.param_headers(key="A") is None
    cm.clean_headers()
    assert cm.headers == dict()
    cm.add_param_headers(key="H", value="B")
    assert cm.exist_param_headers(key="H")
    assert not cm.exist_param_headers(key="B")
    cm.del_param_headers(key="H")
    assert not cm.exist_param_headers(key="H")


def test_bad_connection():
    """Test bad connection."""
    cm = ConnectionManager(base_url="http://not.real.domain")
    with pytest.raises(KeycloakConnectionError):
        cm.raw_get(path="bad")
    with pytest.raises(KeycloakConnectionError):
        cm.raw_delete(path="bad")
    with pytest.raises(KeycloakConnectionError):
        cm.raw_post(path="bad", data={})
    with pytest.raises(KeycloakConnectionError):
        cm.raw_put(path="bad", data={})


@pytest.mark.asyncio
async def a_test_bad_connection():
    """Test bad connection."""
    cm = ConnectionManager(base_url="http://not.real.domain")
    with pytest.raises(KeycloakConnectionError):
        await cm.a_raw_get(path="bad")
    with pytest.raises(KeycloakConnectionError):
        await cm.a_raw_delete(path="bad")
    with pytest.raises(KeycloakConnectionError):
        await cm.a_raw_post(path="bad", data={})
    with pytest.raises(KeycloakConnectionError):
        await cm.a_raw_put(path="bad", data={})


def test_counter_part():
    """Test that each function has its async counter part."""
    con_methods = [
        func for func in dir(ConnectionManager) if callable(getattr(ConnectionManager, func))
    ]
    sync_methods = [method for method in con_methods if method.startswith("a_")]

    for method in sync_methods:
        async_method = method[2:]
        assert (async_method in con_methods) is True
        sync_sign = signature(getattr(ConnectionManager, method))
        async_sign = signature(getattr(ConnectionManager, async_method))
        assert sync_sign.parameters == async_sign.parameters
