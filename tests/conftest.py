"""Fixtures for tests."""

import ipaddress
import os
import uuid
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from keycloak import KeycloakAdmin, KeycloakOpenID


class KeycloakTestEnv(object):
    """Wrapper for test Keycloak connection configuration.

    :param host: Hostname
    :type host: str
    :param port: Port
    :type port: str
    :param username: Admin username
    :type username: str
    :param password: Admin password
    :type password: str
    """

    def __init__(
        self,
        host: str = os.environ["KEYCLOAK_HOST"],
        port: str = os.environ["KEYCLOAK_PORT"],
        username: str = os.environ["KEYCLOAK_ADMIN"],
        password: str = os.environ["KEYCLOAK_ADMIN_PASSWORD"],
    ):
        """Init method.

        :param host: Hostname
        :type host: str
        :param port: Port
        :type port: str
        :param username: Admin username
        :type username: str
        :param password: Admin password
        :type password: str
        """
        self.KEYCLOAK_HOST = host
        self.KEYCLOAK_PORT = port
        self.KEYCLOAK_ADMIN = username
        self.KEYCLOAK_ADMIN_PASSWORD = password

    @property
    def KEYCLOAK_HOST(self):
        """Hostname getter.

        :returns: Keycloak host
        :rtype: str
        """
        return self._KEYCLOAK_HOST

    @KEYCLOAK_HOST.setter
    def KEYCLOAK_HOST(self, value: str):
        """Hostname setter.

        :param value: Keycloak host
        :type value: str
        """
        self._KEYCLOAK_HOST = value

    @property
    def KEYCLOAK_PORT(self):
        """Port getter.

        :returns: Keycloak port
        :rtype: str
        """
        return self._KEYCLOAK_PORT

    @KEYCLOAK_PORT.setter
    def KEYCLOAK_PORT(self, value: str):
        """Port setter.

        :param value: Keycloak port
        :type value: str
        """
        self._KEYCLOAK_PORT = value

    @property
    def KEYCLOAK_ADMIN(self):
        """Admin username getter.

        :returns: Admin username
        :rtype: str
        """
        return self._KEYCLOAK_ADMIN

    @KEYCLOAK_ADMIN.setter
    def KEYCLOAK_ADMIN(self, value: str):
        """Admin username setter.

        :param value: Admin username
        :type value: str
        """
        self._KEYCLOAK_ADMIN = value

    @property
    def KEYCLOAK_ADMIN_PASSWORD(self):
        """Admin password getter.

        :returns: Admin password
        :rtype: str
        """
        return self._KEYCLOAK_ADMIN_PASSWORD

    @KEYCLOAK_ADMIN_PASSWORD.setter
    def KEYCLOAK_ADMIN_PASSWORD(self, value: str):
        """Admin password setter.

        :param value: Admin password
        :type value: str
        """
        self._KEYCLOAK_ADMIN_PASSWORD = value


@pytest.fixture
def env():
    """Fixture for getting the test environment configuration object.

    :returns: Keycloak test environment object
    :rtype: KeycloakTestEnv
    """
    return KeycloakTestEnv()


@pytest_asyncio.fixture
async def admin(env: KeycloakTestEnv):
    """Fixture for initialized KeycloakAdmin class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :returns: Keycloak admin
    :rtype: KeycloakAdmin
    """
    admin = KeycloakAdmin(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        username=env.KEYCLOAK_ADMIN,
        password=env.KEYCLOAK_ADMIN_PASSWORD,
    )
    await admin.connect()
    return admin


@pytest_asyncio.fixture
async def oid(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for initialized KeycloakOpenID class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client
    :rtype: KeycloakOpenID
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    client_id = await admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": True,
            "protocol": "openid-connect",
        }
    )
    # Return OID
    yield KeycloakOpenID(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        realm_name=realm,
        client_id=client,
    )
    # Cleanup
    await admin.delete_client(client_id=client_id)


@pytest_asyncio.fixture
async def oid_with_credentials(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for an initialized KeycloakOpenID class and a random user credentials.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client with user credentials
    :rtype: Tuple[KeycloakOpenID, str, str]
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = await admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
        }
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = await admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "credentials": [{"type": "password", "value": password}],
        }
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    await admin.delete_client(client_id=client_id)
    await admin.delete_user(user_id=user_id)


@pytest_asyncio.fixture
async def oid_with_credentials_authz(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for an initialized KeycloakOpenID class and a random user credentials.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client configured as an authorization server with client credentials
    :rtype: Tuple[KeycloakOpenID, str, str]
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = await admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
            "authorizationServicesEnabled": True,
            "serviceAccountsEnabled": True,
        }
    )
    role = await admin.get_realm_role(role_name="offline_access")
    payload = {
        "name": "test-authz-rb-policy",
        "roles": [{"id": role["id"]}],
    }
    await admin.create_client_authz_role_based_policy(
        client_id=client_id,
        payload=payload,
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = await admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "credentials": [{"type": "password", "value": password}],
        }
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    await admin.delete_client(client_id=client_id)
    await admin.delete_user(user_id=user_id)


@pytest_asyncio.fixture
async def realm(admin: KeycloakAdmin) -> str:
    """Fixture for a new random realm.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak realm
    :rtype: str
    """
    realm_name = str(uuid.uuid4())
    await admin.create_realm(payload={"realm": realm_name, "enabled": True})
    yield realm_name
    await admin.delete_realm(realm_name=realm_name)


@pytest_asyncio.fixture
async def user(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random user.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak user
    :rtype: str
    """
    admin.realm_name = realm
    username = str(uuid.uuid4())
    user_id = await admin.create_user(payload={"username": username, "email": f"{username}@test.test"})
    yield user_id
    await admin.delete_user(user_id=user_id)


@pytest_asyncio.fixture
async def group(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random group.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak group
    :rtype: str
    """
    admin.realm_name = realm
    group_name = str(uuid.uuid4())
    group_id = await admin.create_group(payload={"name": group_name})
    yield group_id
    await admin.delete_group(group_id=group_id)


@pytest_asyncio.fixture
async def client(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random client.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak client id
    :rtype: str
    """
    admin.realm_name = realm
    client = str(uuid.uuid4())
    client_id = await admin.create_client(payload={"name": client, "clientId": client})
    yield client_id
    await admin.delete_client(client_id=client_id)


@pytest_asyncio.fixture
async def client_role(admin: KeycloakAdmin, realm: str, client: str) -> str:
    """Fixture for a new random client role.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param client: Keycloak client
    :type client: str
    :yields: Keycloak client role
    :rtype: str
    """
    admin.realm_name = realm
    role = str(uuid.uuid4())
    await admin.create_client_role(client, {"name": role, "composite": False})
    yield role
    await admin.delete_client_role(client, role)


@pytest_asyncio.fixture
async def composite_client_role(admin: KeycloakAdmin, realm: str, client: str, client_role: str) -> str:
    """Fixture for a new random composite client role.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param client: Keycloak client
    :type client: str
    :param client_role: Keycloak client role
    :type client_role: str
    :yields: Composite client role
    :rtype: str
    """
    admin.realm_name = realm
    role = str(uuid.uuid4())
    await admin.create_client_role(client, {"name": role, "composite": True})
    role_repr = await admin.get_client_role(client, client_role)
    await admin.add_composite_client_roles_to_role(client, role, roles=[role_repr])
    yield role
    await admin.delete_client_role(client, role)


@pytest.fixture
def selfsigned_cert():
    """Generate self signed certificate for a hostname, and optional IP addresses.

    :returns: Selfsigned certificate
    :rtype: Tuple[str, str]
    """
    hostname = "testcert"
    ip_addresses = None
    key = None
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    alt_names = [x509.DNSName(hostname)]

    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    san = x509.SubjectAlternativeName(alt_names)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem
