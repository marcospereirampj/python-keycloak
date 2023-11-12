"""Connection test module."""

import pytest

from keycloak.connection import ConnectionManager
from keycloak.exceptions import KeycloakConnectionError


def test_connection_proxy():
    """Test proxies of connection manager."""
    cm = ConnectionManager(
        base_url="http://test.test", proxies={"http://test.test": "localhost:8080"}
    )
    assert cm._s.proxies == {"http://test.test": "localhost:8080"}


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
