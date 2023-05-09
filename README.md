[![CircleCI](https://github.com/marcospereirampj/python-keycloak/actions/workflows/daily.yaml/badge.svg)](https://github.com/marcospereirampj/python-keycloak/)
[![Documentation Status](https://readthedocs.org/projects/python-keycloak/badge/?version=latest)](http://python-keycloak.readthedocs.io/en/latest/?badge=latest)

# Python Keycloak

For review- see https://github.com/marcospereirampj/python-keycloak

**python-keycloak** is a Python package providing access to the Keycloak API.

## Installation

### Via Pypi Package:

`$ pip install python-keycloak`

### Manually

`$ python setup.py install`

## Dependencies

python-keycloak depends on:

- Python 3
- [requests](https://requests.readthedocs.io)
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

# Get WellKnown
config_well_known = keycloak_openid.well_known()

# Get Code With Oauth Authorization Request
auth_url = keycloak_openid.auth_url(
    redirect_uri="your_call_back_url",
    scope="email",
    state="your_state_info")

# Get Access Token With Code
access_token = keycloak_openid.token(
    grant_type='authorization_code',
    code='the_code_you_get_from_auth_url_callback',
    redirect_uri="your_call_back_url")


# Get Token
token = keycloak_openid.token("user", "password")
token = keycloak_openid.token("user", "password", totp="012345")

# Get token using Token Exchange
token = keycloak_openid.exchange_token(token['access_token'], "my_client", "other_client", "some_user")

# Get Userinfo
userinfo = keycloak_openid.userinfo(token['access_token'])

# Refresh token
token = keycloak_openid.refresh_token(token['refresh_token'])

# Logout
keycloak_openid.logout(token['refresh_token'])

# Get Certs
certs = keycloak_openid.certs()

# Get RPT (Entitlement)
token = keycloak_openid.token("user", "password")
rpt = keycloak_openid.entitlement(token['access_token'], "resource_id")

# Introspect RPT
token_rpt_info = keycloak_openid.introspect(keycloak_openid.introspect(token['access_token'], rpt=rpt['rpt'],
                                                                       token_type_hint="requesting_party_token"))

# Introspect Token
token_info = keycloak_openid.introspect(token['access_token'])

# Decode Token
KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
options = {"verify_signature": True, "verify_aud": True, "verify_exp": True}
token_info = keycloak_openid.decode_token(token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)

# Get permissions by token
token = keycloak_openid.token("user", "password")
keycloak_openid.load_authorization_config("example-authz-config.json")
policies = keycloak_openid.get_policies(token['access_token'], method_token_info='decode', key=KEYCLOAK_PUBLIC_KEY)
permissions = keycloak_openid.get_permissions(token['access_token'], method_token_info='introspect')

# Get UMA-permissions by token
token = keycloak_openid.token("user", "password")
permissions = keycloak_openid.uma_permissions(token['access_token'])

# Get UMA-permissions by token with specific resource and scope requested
token = keycloak_openid.token("user", "password")
permissions = keycloak_openid.uma_permissions(token['access_token'], permissions="Resource#Scope")

# Get auth status for a specific resource and scope by token
token = keycloak_openid.token("user", "password")
auth_status = keycloak_openid.has_uma_access(token['access_token'], "Resource#Scope")


# KEYCLOAK ADMIN

from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://localhost:8080/",
                        username='example-admin',
                        password='secret',
                        realm_name="master",
                        user_realm_name="only_if_other_realm_than_master",
                        client_id="my_client",
                        client_secret_key="client-secret",
                        verify=True)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# Add user
new_user = keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example"})

# Add user and raise exception if username already exists
# exist_ok currently defaults to True for backwards compatibility reasons
new_user = keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example"},
                                      exist_ok=False)

# Add user and set password
new_user = keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example",
                    "credentials": [{"value": "secret","type": "password",}]})

# Add user and specify a locale
new_user = keycloak_admin.create_user({"email": "example@example.fr",
                                       "username": "example@example.fr",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example",
                                       "attributes": {
                                           "locale": ["fr"]
                                       }})

# User counter
count_users = keycloak_admin.users_count()

# Get users Returns a list of users, filtered according to query parameters
users = keycloak_admin.get_users({})

# Get user ID from username
user_id_keycloak = keycloak_admin.get_user_id("username-keycloak")

# Get User
user = keycloak_admin.get_user("user-id-keycloak")

# Update User
response = keycloak_admin.update_user(user_id="user-id-keycloak",
                                      payload={'firstName': 'Example Update'})

# Update User Password
response = keycloak_admin.set_user_password(user_id="user-id-keycloak", password="secret", temporary=True)

# Get User Credentials
credentials = keycloak_admin.get_credentials(user_id='user_id')

# Get User Credential by ID
credential = keycloak_admin.get_credential(user_id='user_id', credential_id='credential_id')

# Delete User Credential
response = keycloak_admin.delete_credential(user_id='user_id', credential_id='credential_id')

# Delete User
response = keycloak_admin.delete_user(user_id="user-id-keycloak")

# Get consents granted by the user
consents = keycloak_admin.consents_user(user_id="user-id-keycloak")

# Send User Action
response = keycloak_admin.send_update_account(user_id="user-id-keycloak",
                                              payload=['UPDATE_PASSWORD'])

# Send Verify Email
response = keycloak_admin.send_verify_email(user_id="user-id-keycloak")

# Get sessions associated with the user
sessions = keycloak_admin.get_sessions(user_id="user-id-keycloak")

# Get themes, social providers, auth providers, and event listeners available on this server
server_info = keycloak_admin.get_server_info()

# Get clients belonging to the realm Returns a list of clients belonging to the realm
clients = keycloak_admin.get_clients()

# Get client - id (not client-id) from client by name
client_id = keycloak_admin.get_client_id("my-client")

# Get representation of the client - id of client (not client-id)
client = keycloak_admin.get_client(client_id="client_id")

# Get all roles for the realm or client
realm_roles = keycloak_admin.get_realm_roles()

# Get all roles for the client
client_roles = keycloak_admin.get_client_roles(client_id="client_id")

# Get client role
role = keycloak_admin.get_client_role(client_id="client_id", role_name="role_name")

# Warning: Deprecated
# Get client role id from name
role_id = keycloak_admin.get_client_role_id(client_id="client_id", role_name="test")

# Create client role
keycloak_admin.create_client_role(client_role_id='client_id', payload={'name': 'roleName', 'clientRole': True})

# Assign client role to user. Note that BOTH role_name and role_id appear to be required.
keycloak_admin.assign_client_role(client_id="client_id", user_id="user_id", role_id="role_id", role_name="test")

# Retrieve client roles of a user.
keycloak_admin.get_client_roles_of_user(user_id="user_id", client_id="client_id")

# Retrieve available client roles of a user.
keycloak_admin.get_available_client_roles_of_user(user_id="user_id", client_id="client_id")

# Retrieve composite client roles of a user.
keycloak_admin.get_composite_client_roles_of_user(user_id="user_id", client_id="client_id")

# Delete client roles of a user.
keycloak_admin.delete_client_roles_of_user(client_id="client_id", user_id="user_id", roles={"id": "role-id"})
keycloak_admin.delete_client_roles_of_user(client_id="client_id", user_id="user_id", roles=[{"id": "role-id_1"}, {"id": "role-id_2"}])

# Get the client authorization settings
client_authz_settings = get_client_authz_settings(client_id="client_id")

# Get all client authorization resources
client_resources = get_client_authz_resources(client_id="client_id")

# Get all client authorization scopes
client_scopes = get_client_authz_scopes(client_id="client_id")

# Get all client authorization permissions
client_permissions = get_client_authz_permissions(client_id="client_id")

# Get all client authorization policies
client_policies = get_client_authz_policies(client_id="client_id")

# Create new group
group = keycloak_admin.create_group({"name": "Example Group"})

# Get all groups
groups = keycloak_admin.get_groups()

# Get group
group = keycloak_admin.get_group(group_id='group_id')

# Get group by name
group = keycloak_admin.get_group_by_path(path='/group/subgroup', search_in_subgroups=True)

# Function to trigger user sync from provider
sync_users(storage_id="storage_di", action="action")

# Get client role id from name
role_id = keycloak_admin.get_client_role_id(client_id=client_id, role_name="test")

# Assign client role to user. Note that BOTH role_name and role_id appear to be required.
keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, role_id=role_id, role_name="test")

# Assign realm roles to user
keycloak_admin.assign_realm_roles(user_id=user_id, roles=realm_roles)

# Assign realm roles to client's scope
keycloak_admin.assign_realm_roles_to_client_scope(client_id=client_id, roles=realm_roles)

# Get realm roles assigned to client's scope
keycloak_admin.get_realm_roles_of_client_scope(client_id=client_id)

# Remove realm roles assigned to client's scope
keycloak_admin.delete_realm_roles_of_client_scope(client_id=client_id, roles=realm_roles)

another_client_id = keycloak_admin.get_client_id("my-client-2")

# Assign client roles to client's scope
keycloak_admin.assign_client_roles_to_client_scope(client_id=another_client_id, client_roles_owner_id=client_id, roles=client_roles)

# Get client roles assigned to client's scope
keycloak_admin.get_client_roles_of_client_scope(client_id=another_client_id, client_roles_owner_id=client_id)

# Remove client roles assigned to client's scope
keycloak_admin.delete_client_roles_of_client_scope(client_id=another_client_id, client_roles_owner_id=client_id, roles=client_roles)

# Get all ID Providers
idps = keycloak_admin.get_idps()

# Create a new Realm
keycloak_admin.create_realm(payload={"realm": "demo"}, skip_exists=False)

# Changing Realm
keycloak_admin = KeycloakAdmin(realm_name="main", ...)
keycloak_admin.get_users() # Get user in main realm
keycloak_admin.realm_name = "demo" # Change realm to 'demo'
keycloak_admin.get_users() # Get users in realm 'demo'
keycloak_admin.create_user(...) # Creates a new user in 'demo'

# KEYCLOAK UMA

from keycloak import KeycloakOpenIDConnection
from keycloak import KeycloakUMA

keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://localhost:8080/",
                        realm_name="master",
                        client_id="my_client",
                        client_secret_key="client-secret")

keycloak_uma = KeycloakUMA(connection=keycloak_connection)

# Create a resource set
resource_set = keycloak_uma.resource_set_create({
                "name": "example_resource",
                "scopes": ["example:read", "example:write"],
                "type": "urn:example"})

# List resource sets
resource_sets = uma.resource_set_list()

# get resource set
latest_resource = uma.resource_set_read(resource_set["_id"])

# update resource set
latest_resource["name"] = "New Resource Name"
uma.resource_set_update(resource_set["_id"], latest_resource)

# delete resource set
uma.resource_set_delete(resource_id=resource_set["_id"])
```
