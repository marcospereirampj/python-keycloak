"""Fixtures for tests."""

import ipaddress
import os
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import freezegun
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakOpenIDConnection, KeycloakUMA


class KeycloakTestEnv:
    """
    Wrapper for test Keycloak connection configuration.

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
    ) -> None:
        """
        Init method.

        :param host: Hostname
        :type host: str
        :param port: Port
        :type port: str
        :param username: Admin username
        :type username: str
        :param password: Admin password
        :type password: str
        """
        self.keycloak_host = host
        self.keycloak_port = port
        self.keycloak_admin = username
        self.keycloak_admin_password = password

    @property
    def keycloak_host(self) -> str:
        """
        Hostname getter.

        :returns: Keycloak host
        :rtype: str
        """
        return self._keycloak_host

    @keycloak_host.setter
    def keycloak_host(self, value: str) -> None:
        """
        Hostname setter.

        :param value: Keycloak host
        :type value: str
        """
        self._keycloak_host = value

    @property
    def keycloak_port(self) -> str:
        """
        Port getter.

        :returns: Keycloak port
        :rtype: str
        """
        return self._keycloak_port

    @keycloak_port.setter
    def keycloak_port(self, value: str) -> None:
        """
        Port setter.

        :param value: Keycloak port
        :type value: str
        """
        self._keycloak_port = value

    @property
    def keycloak_admin(self) -> str:
        """
        Admin username getter.

        :returns: Admin username
        :rtype: str
        """
        return self._keycloak_admin

    @keycloak_admin.setter
    def keycloak_admin(self, value: str) -> None:
        """
        Admin username setter.

        :param value: Admin username
        :type value: str
        """
        self._keycloak_admin = value

    @property
    def keycloak_admin_password(self) -> str:
        """
        Admin password getter.

        :returns: Admin password
        :rtype: str
        """
        return self._keycloak_admin_password

    @keycloak_admin_password.setter
    def keycloak_admin_password(self, value: str) -> None:
        """
        Admin password setter.

        :param value: Admin password
        :type value: str
        """
        self._keycloak_admin_password = value


@pytest.fixture
def env() -> KeycloakTestEnv:
    """
    Fixture for getting the test environment configuration object.

    :returns: Keycloak test environment object
    :rtype: KeycloakTestEnv
    """
    return KeycloakTestEnv()


@pytest.fixture
def admin(env: KeycloakTestEnv) -> KeycloakAdmin:
    """
    Fixture for initialized KeycloakAdmin class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :returns: Keycloak admin
    :rtype: KeycloakAdmin
    """
    return KeycloakAdmin(
        server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
        username=env.keycloak_admin,
        password=env.keycloak_admin_password,
    )


@pytest.fixture
@freezegun.freeze_time("2023-02-25 10:00:00")
def admin_frozen(env: KeycloakTestEnv) -> KeycloakAdmin:
    """
    Fixture for initialized KeycloakAdmin class, with time frozen.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :returns: Keycloak admin
    :rtype: KeycloakAdmin
    """
    return KeycloakAdmin(
        server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
        username=env.keycloak_admin,
        password=env.keycloak_admin_password,
    )


@pytest.fixture
def oid(
    env: KeycloakTestEnv,
    realm: str,
    admin: KeycloakAdmin,
) -> Generator[KeycloakOpenID, None, None]:
    """
    Fixture for initialized KeycloakOpenID class.

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
    admin.change_current_realm(realm)
    # Create client
    client = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": True,
            "protocol": "openid-connect",
        },
    )
    # Return OID
    yield KeycloakOpenID(
        server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
        realm_name=realm,
        client_id=client,
    )
    # Cleanup
    admin.delete_client(client_id=client_id)


@pytest.fixture
def oid_with_credentials(
    env: KeycloakTestEnv,
    realm: str,
    admin: KeycloakAdmin,
) -> Generator[tuple[KeycloakOpenID, str, str], None, None]:
    """
    Fixture for an initialized KeycloakOpenID class and a random user credentials.

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
    admin.change_current_realm(realm)
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
        },
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "firstName": "first",
            "lastName": "last",
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    admin.delete_client(client_id=client_id)
    admin.delete_user(user_id=user_id)


@pytest.fixture
def oid_with_credentials_authz(
    env: KeycloakTestEnv,
    realm: str,
    admin: KeycloakAdmin,
) -> Generator[tuple[KeycloakOpenID, str, str], None, None]:
    """
    Fixture for an initialized KeycloakOpenID class and a random user credentials.

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
    admin.change_current_realm(realm)
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = admin.create_client(
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
        },
    )
    admin.create_client_authz_role_based_policy(
        client_id=client_id,
        payload={
            "name": "test-authz-rb-policy",
            "roles": [{"id": admin.get_realm_role(role_name="offline_access")["id"]}],
        },
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "emailVerified": True,
            "firstName": "first",
            "lastName": "last",
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    admin.delete_client(client_id=client_id)
    admin.delete_user(user_id=user_id)


@pytest.fixture
def oid_with_credentials_device(
    env: KeycloakTestEnv,
    realm: str,
    admin: KeycloakAdmin,
) -> Generator[tuple[KeycloakOpenID, str, str], None, None]:
    """
    Fixture for an initialized KeycloakOpenID class and a random user credentials.

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
    admin.change_current_realm(realm)
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
            "attributes": {"oauth2.device.authorization.grant.enabled": True},
        },
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "firstName": "first",
            "lastName": "last",
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    admin.delete_client(client_id=client_id)
    admin.delete_user(user_id=user_id)


@pytest.fixture
def realm(admin: KeycloakAdmin) -> Generator[str, None, None]:
    """
    Fixture for a new random realm.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak realm
    :rtype: str
    """
    realm_name = str(uuid.uuid4())
    admin.create_realm(payload={"realm": realm_name, "enabled": True})
    yield realm_name
    admin.delete_realm(realm_name=realm_name)


@pytest.fixture
def user(admin: KeycloakAdmin, realm: str) -> Generator[str, None, None]:
    """
    Fixture for a new random user.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak user
    :rtype: str
    """
    admin.change_current_realm(realm)
    username = str(uuid.uuid4())
    user_id = admin.create_user(payload={"username": username, "email": f"{username}@test.test"})
    yield user_id
    admin.delete_user(user_id=user_id)


@pytest.fixture
def group(admin: KeycloakAdmin, realm: str) -> Generator[str, None, None]:
    """
    Fixture for a new random group.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak group
    :rtype: str
    """
    admin.change_current_realm(realm)
    group_name = str(uuid.uuid4())
    group_id = admin.create_group(payload={"name": group_name})
    yield group_id
    admin.delete_group(group_id=group_id)


@pytest.fixture
def client(admin: KeycloakAdmin, realm: str) -> Generator[str, None, None]:
    """
    Fixture for a new random client.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak client id
    :rtype: str
    """
    admin.change_current_realm(realm)
    client = str(uuid.uuid4())
    client_id = admin.create_client(payload={"name": client, "clientId": client})
    yield client_id
    admin.delete_client(client_id=client_id)


@pytest.fixture
def client_role(admin: KeycloakAdmin, realm: str, client: str) -> Generator[str, None, None]:
    """
    Fixture for a new random client role.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param client: Keycloak client
    :type client: str
    :yields: Keycloak client role
    :rtype: str
    """
    admin.change_current_realm(realm)
    role = str(uuid.uuid4())
    admin.create_client_role(client, {"name": role, "composite": False})
    yield role
    admin.delete_client_role(client, role)


@pytest.fixture
def composite_client_role(
    admin: KeycloakAdmin,
    realm: str,
    client: str,
    client_role: str,
) -> Generator[str, None, None]:
    """
    Fixture for a new random composite client role.

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
    admin.change_current_realm(realm)
    role = str(uuid.uuid4())
    admin.create_client_role(client, {"name": role, "composite": True})
    role_repr = admin.get_client_role(client, client_role)
    admin.add_composite_client_roles_to_role(client, role, roles=[role_repr])
    yield role
    admin.delete_client_role(client, role)


@pytest.fixture
def selfsigned_cert() -> tuple[str, str]:
    """
    Generate self signed certificate for a hostname, and optional IP addresses.

    :returns: Selfsigned certificate
    :rtype: Tuple[str, str]
    """
    hostname = "testcert"
    ip_addresses = None
    key = None
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
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
    now = datetime.now(tz=timezone.utc)
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


@pytest.fixture
def oid_connection_with_authz(
    oid_with_credentials_authz: tuple[KeycloakOpenID, str, str],
) -> KeycloakOpenIDConnection:
    """
    Fixture for initialized KeycloakUMA class.

    :param oid_with_credentials_authz: Keycloak OpenID client with pre-configured user credentials
    :type oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]
    :yields: Keycloak OpenID connection manager
    :rtype: KeycloakOpenIDConnection
    """
    oid, _, _ = oid_with_credentials_authz
    return KeycloakOpenIDConnection(
        server_url=oid.connection.base_url,
        realm_name=oid.realm_name,
        client_id=oid.client_id,
        client_secret_key=oid.client_secret_key,
        timeout=60,
    )


@pytest.fixture
def uma(oid_connection_with_authz: KeycloakOpenIDConnection) -> KeycloakUMA:
    """
    Fixture for initialized KeycloakUMA class.

    :param oid_connection_with_authz: Keycloak open id connection with pre-configured authz client
    :type oid_connection_with_authz: KeycloakOpenIDConnection
    :yields: Keycloak OpenID client
    :rtype: KeycloakOpenID
    """
    connection = oid_connection_with_authz
    # Return UMA
    return KeycloakUMA(connection=connection)
