"""Connection test module."""

from inspect import iscoroutinefunction, signature

import pytest

from keycloak.connection import ConnectionManager
from keycloak.exceptions import KeycloakConnectionError


def test_connection_proxy() -> None:
    """Test proxies of connection manager."""
    cm = ConnectionManager(
        base_url="http://test.test",
        proxies={"http://test.test": "http://localhost:8080"},
    )
    assert cm._s.proxies == {"http://test.test": "http://localhost:8080"}


def test_headers() -> None:
    """Test headers manipulation."""
    cm = ConnectionManager(base_url="http://test.test", headers={"H": "A"})
    assert cm.param_headers(key="H") == "A"
    assert cm.param_headers(key="A") is None
    cm.clean_headers()
    assert cm.headers == {}
    cm.add_param_headers(key="H", value="B")
    assert cm.exist_param_headers(key="H")
    assert not cm.exist_param_headers(key="B")
    cm.del_param_headers(key="H")
    assert not cm.exist_param_headers(key="H")


def test_bad_connection() -> None:
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
async def a_test_bad_connection() -> None:
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


def test_counter_part() -> None:
    """Test that each function has its async counter part."""
    con_methods = [
        func for func in dir(ConnectionManager) if callable(getattr(ConnectionManager, func))
    ]
    sync_methods = [
        method
        for method in con_methods
        if not method.startswith("a_") and not method.startswith("_")
    ]
    async_methods = [
        method for method in con_methods if iscoroutinefunction(getattr(ConnectionManager, method))
    ]

    for method in sync_methods:
        if method in [
            "aclose",
            "add_param_headers",
            "del_param_headers",
            "clean_headers",
            "exist_param_headers",
            "param_headers",
        ]:
            continue
        async_method = f"a_{method}"
        assert (async_method in con_methods) is True
        sync_sign = signature(getattr(ConnectionManager, method))
        async_sign = signature(getattr(ConnectionManager, async_method))
        assert sync_sign.parameters == async_sign.parameters

    for async_method in async_methods:
        if async_method == "aclose":
            continue
        if async_method[2:].startswith("_"):
            continue

        assert async_method[2:] in sync_methods


def test_build_url() -> None:
    """Test URL building and sub-path preservation."""
    # Scenario 1: Base URL WITHOUT a trailing slash
    cm = ConnectionManager(base_url="http://test.test/auth")

    assert cm._build_url("realms/master") == "http://test.test/auth/realms/master"
    assert cm._build_url("/realms/master") == "http://test.test/auth/realms/master"

    # Scenario 2: Base URL WITH a trailing slash
    cm_slashed = ConnectionManager(base_url="http://test.test/auth/")

    assert cm_slashed._build_url("realms/master") == "http://test.test/auth/realms/master"
    assert cm_slashed._build_url("/realms/master") == "http://test.test/auth/realms/master"

    # Scenario 3: Path is already an absolute URL
    assert cm._build_url("http://absolute.test/realms") == "http://absolute.test/realms"
    assert cm._build_url("https://absolute.test/realms") == "https://absolute.test/realms"

    # Scenario 4: Empty base URL
    cm_empty = ConnectionManager(base_url="")

    assert cm_empty._build_url("realms/master") == "realms/master"
    assert cm_empty._build_url("/realms/master") == "/realms/master"
