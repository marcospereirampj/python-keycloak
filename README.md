[![Documentation Status](https://readthedocs.org/projects/python-keycloak/badge/?version=latest)](http://python-keycloak.readthedocs.io/en/latest/?badge=latest)

# Async Python Keycloak fork
This repo is a fork of https://github.com/marcospereirampj/python-keycloak at version 2.9.0 by Indoc Research to support async.

# Python Keycloak

For review- see https://github.com/marcospereirampj/python-keycloak

**python-keycloak** is a Python package providing access to the Keycloak API.

## Installation

### Via Pypi Package:

`$ pip install python-keycloak`

### Manually

`$ pip install .`

## Dependencies

python-keycloak depends on:

- Python 3
- [httpx](https://www.python-httpx.org/)
- [python-jose](http://python-jose.readthedocs.io/en/latest/)
- [urllib3](https://urllib3.readthedocs.io/en/stable/)

### Tests Dependencies

- [tox](https://tox.readthedocs.io/)
- [pytest](https://docs.pytest.org/en/latest/)
- [pytest-cov](https://github.com/pytest-dev/pytest-cov)
- [wheel](https://github.com/pypa/wheel)

## Bug reports

Please report bugs and feature requests at
https://github.com/marcospereirampj/python-keycloak/issues

## Documentation

The documentation for python-keycloak is available on [readthedocs](http://python-keycloak.readthedocs.io).

## Contributors

- [Agriness Team](http://www.agriness.com/pt/)
- [Marcos Pereira](marcospereira.mpj@gmail.com)
- [Martin Devlin](https://bitbucket.org/devlinmpearson/)
- [Shon T. Urbas](https://bitbucket.org/surbas/)
- [Markus Spanier](https://bitbucket.org/spanierm/)
- [Remco Kranenburg](https://bitbucket.org/Remco47/)
- [Armin](https://bitbucket.org/arminfelder/)
- [njordr](https://bitbucket.org/njordr/)
- [Josha Inglis](https://bitbucket.org/joshainglis/)
- [Alex](https://bitbucket.org/alex_zel/)
- [Ewan Jone](https://bitbucket.org/kisamoto/)
- [Lukas Martini](https://github.com/lutoma)
- [Adamatics](https://www.adamatics.com)

## Usage

```python
from keycloak import KeycloakOpenID

# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                 client_id="example_client",
                                 realm_name="example_realm",
                                 client_secret_key="secret")

# Get WellKnow
config_well_known = await keycloak_openid.well_known()

# Get Code With Oauth Authorization Request
auth_url = await keycloak_openid.auth_url(
    redirect_uri="your_call_back_url",
    scope="email",
    state="your_state_info")

# Get Access Token With Code
access_token = await keycloak_openid.token(
    grant_type='authorization_code',
    code='the_code_you_get_from_auth_url_callback',
    redirect_uri="your_call_back_url")


# Get Token
token = await keycloak_openid.token("user", "password")
token = await keycloak_openid.token("user", "password", totp="012345")

# Get token using Token Exchange
token = await keycloak_openid.exchange_token(token['access_token'], "my_client", "other_client", "some_user")

# Get Userinfo
userinfo = await keycloak_openid.userinfo(token['access_token'])

# Refresh token
token = await keycloak_openid.refresh_token(token['refresh_token'])

# Logout
await keycloak_openid.logout(token['refresh_token'])

# Get Certs
certs = await keycloak_openid.certs()

# Get RPT (Entitlement)
token = await keycloak_openid.token("user", "password")
rpt = await keycloak_openid.entitlement(token['access_token'], "resource_id")

# Instropect RPT
token_rpt_info = await keycloak_openid.introspect(keycloak_openid.introspect(token['access_token'], rpt=rpt['rpt'],
                                                                       token_type_hint="requesting_party_token"))

# Introspect Token
token_info = await keycloak_openid.introspect(token['access_token'])

# Decode Token
KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
options = {"verify_signature": True, "verify_aud": True, "verify_exp": True}
token_info = await keycloak_openid.decode_token(token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)

# Get permissions by token
token = await keycloak_openid.token("user", "password")
await keycloak_openid.load_authorization_config("example-authz-config.json")
await policies = keycloak_openid.get_policies(token['access_token'], method_token_info='decode', key=KEYCLOAK_PUBLIC_KEY)
await permissions = keycloak_openid.get_permissions(token['access_token'], method_token_info='introspect')

# Get UMA-permissions by token
# Currently unsupported for async version
# token = keycloak_openid.token("user", "password")
# permissions = keycloak_openid.uma_permissions(token['access_token'])

# Get UMA-permissions by token with specific resource and scope requested
# Currently unsupported for async version
# token = keycloak_openid.token("user", "password")
# permissions = keycloak_openid.uma_permissions(token['access_token'], permissions="Resource#Scope")

# Get auth status for a specific resource and scope by token
# Currently unsupported for async version
# token = keycloak_openid.token("user", "password")
# auth_status = keycloak_openid.has_uma_access(token['access_token'], "Resource#Scope")


# KEYCLOAK ADMIN

from keycloak import KeycloakAdmin

keycloak_admin = KeycloakAdmin(server_url="http://localhost:8080/auth/",
                               username='example-admin',
                               password='secret',
                               realm_name="master",
                               user_realm_name="only_if_other_realm_than_master",
                               client_secret_key="client-secret",
                               verify=True)
await keycloak_admin.connect()

# Add user
new_user = await keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example"})

# Add user and raise exception if username already exists
# exist_ok currently defaults to True for backwards compatibility reasons
new_user = await keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example"},
                                      exist_ok=False)

# Add user and set password
new_user = await keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example",
                    "credentials": [{"value": "secret","type": "password",}]})

# Add user and specify a locale
new_user = await keycloak_admin.create_user({"email": "example@example.fr",
                                       "username": "example@example.fr",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example",
                                       "attributes": {
                                           "locale": ["fr"]
                                       }})

# User counter
count_users = await keycloak_admin.users_count()

# Get users Returns a list of users, filtered according to query parameters
users = await keycloak_admin.get_users({})

# Get user ID from username
user_id_keycloak = await keycloak_admin.get_user_id("username-keycloak")

# Get User
user = await keycloak_admin.get_user("user-id-keycloak")

# Update User
response = await keycloak_admin.update_user(user_id="user-id-keycloak",
                                      payload={'firstName': 'Example Update'})

# Update User Password
response = await keycloak_admin.set_user_password(user_id="user-id-keycloak", password="secret", temporary=True)

# Get User Credentials
credentials = await keycloak_admin.get_credentials(user_id='user_id')

# Get User Credential by ID
credential = await keycloak_admin.get_credential(user_id='user_id', credential_id='credential_id')

# Delete User Credential
response = await keycloak_admin.delete_credential(user_id='user_id', credential_id='credential_id')

# Delete User
response = await keycloak_admin.delete_user(user_id="user-id-keycloak")

# Get consents granted by the user
consents = await keycloak_admin.consents_user(user_id="user-id-keycloak")

# Send User Action
response = await keycloak_admin.send_update_account(user_id="user-id-keycloak",
                                              payload=['UPDATE_PASSWORD'])

# Send Verify Email
response = await keycloak_admin.send_verify_email(user_id="user-id-keycloak")

# Get sessions associated with the user
sessions = await keycloak_admin.get_sessions(user_id="user-id-keycloak")

# Get themes, social providers, auth providers, and event listeners available on this server
server_info = await keycloak_admin.get_server_info()

# Get clients belonging to the realm Returns a list of clients belonging to the realm
clients = await keycloak_admin.get_clients()

# Get client - id (not client-id) from client by name
client_id = await keycloak_admin.get_client_id("my-client")

# Get representation of the client - id of client (not client-id)
client = await keycloak_admin.get_client(client_id="client_id")

# Get all roles for the realm or client
realm_roles = await keycloak_admin.get_realm_roles()

# Get all roles for the client
client_roles = await keycloak_admin.get_client_roles(client_id="client_id")

# Get client role
role = await keycloak_admin.get_client_role(client_id="client_id", role_name="role_name")

# Warning: Deprecated
# Get client role id from name
role_id = await keycloak_admin.get_client_role_id(client_id="client_id", role_name="test")

# Create client role
await keycloak_admin.create_client_role(client_role_id='client_id', payload={'name': 'roleName', 'clientRole': True})

# Assign client role to user. Note that BOTH role_name and role_id appear to be required.
await keycloak_admin.assign_client_role(client_id="client_id", user_id="user_id", role_id="role_id", role_name="test")

# Retrieve client roles of a user.
await keycloak_admin.get_client_roles_of_user(user_id="user_id", client_id="client_id")

# Retrieve available client roles of a user.
await keycloak_admin.get_available_client_roles_of_user(user_id="user_id", client_id="client_id")

# Retrieve composite client roles of a user.
await keycloak_admin.get_composite_client_roles_of_user(user_id="user_id", client_id="client_id")

# Delete client roles of a user.
await keycloak_admin.delete_client_roles_of_user(client_id="client_id", user_id="user_id", roles={"id": "role-id"})
await keycloak_admin.delete_client_roles_of_user(client_id="client_id", user_id="user_id", roles=[{"id": "role-id_1"}, {"id": "role-id_2"}])

# Get all client authorization resources
client_resources = get_client_authz_resources(client_id="client_id")

# Get all client authorization scopes
client_scopes = get_client_authz_scopes(client_id="client_id")

# Get all client authorization permissions
client_permissions = get_client_authz_permissions(client_id="client_id")

# Get all client authorization policies
client_policies = get_client_authz_policies(client_id="client_id")

# Create new group
group = await keycloak_admin.create_group({"name": "Example Group"})

# Get all groups
groups = await keycloak_admin.get_groups()

# Get group
group = await keycloak_admin.get_group(group_id='group_id')

# Get group by name
group = await keycloak_admin.get_group_by_path(path='/group/subgroup', search_in_subgroups=True)

# Function to trigger user sync from provider
sync_users(storage_id="storage_di", action="action")

# Get client role id from name
role_id = await keycloak_admin.get_client_role_id(client_id=client_id, role_name="test")

# Get all roles for the realm or client
realm_roles = await keycloak_admin.get_roles()

# Assign client role to user. Note that BOTH role_name and role_id appear to be required.
await keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, role_id=role_id, role_name="test")

# Assign realm roles to user
await keycloak_admin.assign_realm_roles(user_id=user_id, roles=realm_roles)

# Assign realm roles to client's scope
await keycloak_admin.assign_realm_roles_to_client_scope(client_id=client_id, roles=realm_roles)

# Get realm roles assigned to client's scope
await keycloak_admin.get_realm_roles_of_client_scope(client_id=client_id)

# Remove realm roles assigned to client's scope
await keycloak_admin.delete_realm_roles_of_client_scope(client_id=client_id, roles=realm_roles)

another_client_id = await keycloak_admin.get_client_id("my-client-2")

# Assign client roles to client's scope
await keycloak_admin.assign_client_roles_to_client_scope(client_id=another_client_id, client_roles_owner_id=client_id, roles=client_roles)

# Get client roles assigned to client's scope
await keycloak_admin.get_client_roles_of_client_scope(client_id=another_client_id, client_roles_owner_id=client_id)

# Remove client roles assigned to client's scope
await keycloak_admin.delete_client_roles_of_client_scope(client_id=another_client_id, client_roles_owner_id=client_id, roles=client_roles)

# Get all ID Providers
idps = await keycloak_admin.get_idps()

# Create a new Realm
await keycloak_admin.create_realm(payload={"realm": "demo"}, skip_exists=False)

# Changing Realm
await keycloak_admin = KeycloakAdmin(realm_name="main", ...)
await keycloak_admin.get_users() # Get user in main realm
await keycloak_admin.realm_name = "demo" # Change realm to 'demo'
await keycloak_admin.get_users() # Get users in realm 'demo'
await keycloak_admin.create_user(...) # Creates a new user in 'demo'
```
