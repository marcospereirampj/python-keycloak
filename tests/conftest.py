import os

import pytest


@pytest.fixture
def env():
    class KeycloakTestEnv(object):
        KEYCLOAK_HOST = os.environ["KEYCLOAK_HOST"]
        KEYCLOAK_PORT = os.environ["KEYCLOAK_PORT"]
        KEYCLOAK_ADMIN = os.environ["KEYCLOAK_ADMIN"]
        KEYCLOAK_ADMIN_PASSWORD = os.environ["KEYCLOAK_ADMIN_PASSWORD"]

    return KeycloakTestEnv()
