import os
import uuid

import pytest

from keycloak import KeycloakAdmin


@pytest.fixture
def env():
    class KeycloakTestEnv(object):
        KEYCLOAK_HOST = os.environ["KEYCLOAK_HOST"]
        KEYCLOAK_PORT = os.environ["KEYCLOAK_PORT"]
        KEYCLOAK_ADMIN = os.environ["KEYCLOAK_ADMIN"]
        KEYCLOAK_ADMIN_PASSWORD = os.environ["KEYCLOAK_ADMIN_PASSWORD"]

    return KeycloakTestEnv()


@pytest.fixture
def admin(env):
    return KeycloakAdmin(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        username=env.KEYCLOAK_ADMIN,
        password=env.KEYCLOAK_ADMIN_PASSWORD,
    )


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
