import os
import uuid

import pytest

from keycloak import KeycloakAdmin, KeycloakOpenID


class KeycloakTestEnv(object):
    def __init__(
        self,
        host: str = os.environ["KEYCLOAK_HOST"],
        port: str = os.environ["KEYCLOAK_PORT"],
        username: str = os.environ["KEYCLOAK_ADMIN"],
        password: str = os.environ["KEYCLOAK_ADMIN_PASSWORD"],
    ):
        self.KEYCLOAK_HOST = host
        self.KEYCLOAK_PORT = port
        self.KEYCLOAK_ADMIN = username
        self.KEYCLOAK_ADMIN_PASSWORD = password

    @property
    def KEYCLOAK_HOST(self):
        return self._KEYCLOAK_HOST

    @KEYCLOAK_HOST.setter
    def KEYCLOAK_HOST(self, value: str):
        self._KEYCLOAK_HOST = value

    @property
    def KEYCLOAK_PORT(self):
        return self._KEYCLOAK_PORT

    @KEYCLOAK_PORT.setter
    def KEYCLOAK_PORT(self, value: str):
        self._KEYCLOAK_PORT = value

    @property
    def KEYCLOAK_ADMIN(self):
        return self._KEYCLOAK_ADMIN

    @KEYCLOAK_ADMIN.setter
    def KEYCLOAK_ADMIN(self, value: str):
        self._KEYCLOAK_ADMIN = value

    @property
    def KEYCLOAK_ADMIN_PASSWORD(self):
        return self._KEYCLOAK_ADMIN_PASSWORD

    @KEYCLOAK_ADMIN_PASSWORD.setter
    def KEYCLOAK_ADMIN_PASSWORD(self, value: str):
        self._KEYCLOAK_ADMIN_PASSWORD = value


@pytest.fixture
def env():
    return KeycloakTestEnv()


@pytest.fixture
def admin(env: KeycloakTestEnv):
    return KeycloakAdmin(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        username=env.KEYCLOAK_ADMIN,
        password=env.KEYCLOAK_ADMIN_PASSWORD,
    )


@pytest.fixture
def oid(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    client_id = admin.create_client(payload={"name": client, "clientId": client})
    # Return OID
    yield KeycloakOpenID(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        realm_name=realm,
        client_id=client,
    )
    # Cleanup
    admin.delete_client(client_id=client_id)


@pytest.fixture
def realm(admin: KeycloakAdmin) -> str:
    realm_name = str(uuid.uuid4())
    admin.create_realm(payload={"realm": realm_name})
    yield realm_name
    admin.delete_realm(realm_name=realm_name)


@pytest.fixture
def user(admin: KeycloakAdmin, realm: str) -> str:
    admin.realm_name = realm
    username = str(uuid.uuid4())
    user_id = admin.create_user(payload={"username": username, "email": f"{username}@test.test"})
    yield user_id
    admin.delete_user(user_id=user_id)


@pytest.fixture
def group(admin: KeycloakAdmin, realm: str) -> str:
    admin.realm_name = realm
    group_name = str(uuid.uuid4())
    group_id = admin.create_group(payload={"name": group_name})
    yield group_id
    admin.delete_group(group_id=group_id)


@pytest.fixture
def client(admin: KeycloakAdmin, realm: str) -> str:
    admin.realm_name = realm
    client = str(uuid.uuid4())
    client_id = admin.create_client(payload={"name": client, "clientId": client})
    yield client_id
    admin.delete_client(client_id=client_id)
