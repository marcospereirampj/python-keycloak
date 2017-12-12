[![Documentation Status](https://readthedocs.org/projects/python-keycloak/badge/?version=latest)](http://python-keycloak.readthedocs.io/en/latest/?badge=latest)

Python Keycloak
====================

**python-keycloak** is a Python package providing access to the Keycloak API.

## Installation

### Via Pypi Package:

``` $ pip install python-keycloak ```

### Manually

``` $ python setup.py install ```

## Dependencies

python-keycloak depends on:

* Python 3
* [requests](http://docs.python-requests.org/en/master/)
* [python-jose](http://python-jose.readthedocs.io/en/latest/)

### Tests Dependencies

* unittest
* [httmock](https://github.com/patrys/httmock)

## Bug reports

Please report bugs and feature requests at
https://bitbucket.org/agriness/python-keycloak/issues

## Documentation

The documentation for python-keycloak is available on [readthedocs](http://python-keycloak.readthedocs.io).

## Contributors

* [Agriness Team](http://www.agriness.com/pt/)
* [Martin Devlin](martin.devlin@pearson.com) 
* [Shon T. Urbas](shon.urbas@gmail.com>)

## Usage

```python
from keycloak import KeycloakOpenID

# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                    client_id="example_client",
                    realm_name="example_realm",
                    client_secret_key="secret",
                    verify=True)

# Get WellKnow
config_well_know = keycloak_openid.well_know()

# Get Token
token = keycloak_openid.token("user", "password")

# Get Userinfo
userinfo = keycloak_openid.userinfo(token['access_token'])

# Logout
keycloak_openid.logout(token['refresh_token'])

# Get Certs
certs = keycloak_openid.certs()

# Get RPT (Entitlement)
token = keycloak_openid.token("user", "password")
rpt = keycloak_openid.entitlement(token['access_token'], "resource_id")

# Instropect RPT
token_rpt_info = keycloak_openid.introspect(keycloak_openid.introspect(token['access_token'], rpt=rpt['rpt'],
                                     token_type_hint="requesting_party_token"))

# Introspect Token
token_info = keycloak_openid.introspect(token['access_token']))

# Decode Token
KEYCLOAK_PUBLIC_KEY = "secret"
options = {"verify_signature": True, "verify_aud": True, "exp": True}
token_info = keycloak_openid.decode_token(token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)

# Get permissions by token
token = keycloak_openid.token("user", "password")
keycloak_openid.load_authorization_config("example-authz-config.json")
policies = keycloak_openid.get_policies(token['access_token'], method_token_info='decode', key=KEYCLOAK_PUBLIC_KEY)
permissions = keycloak_openid.get_permissions(token['access_token'], method_token_info='introspect')

# KEYCLOAK ADMIN

from keycloak import KeycloakAdmin

keycloak_admin = KeycloakAdmin(server_url="http://localhost:8080/auth/",
                               username='example-admin',
                               password='secret',
                               realm_name="example_realm",
                               verify=True)
        
# Add user                       
new_user = keycloak_admin.create_user({"email": "example@example.com",
                    "username": "example@example.com",
                    "enabled": True,
                    "firstName": "Example",
                    "lastName": "Example",
                    "realmRoles": ["user_default", ],
                    "attributes": {"example": "1,2,3,3,"}})                         

# User counter
count_users = keycloak_admin.users_count()

# Get users Returns a list of users, filtered according to query parameters
users = keycloak_admin.get_users({})

# Get user ID from name
user-id-keycloak = keycloak_admin.get_user_id("example@example.com")

# Get User
user = keycloak_admin.get_user("user-id-keycloak")

# Update User
response = keycloak_admin.update_user(user_id="user-id-keycloak", 
                                      payload={'firstName': 'Example Update'})
                                      
# Delete User
response = keycloak_admin.delete_user(user_id="user-id-keycloak")

# Get consents granted by the user
consents = keycloak_admin.consents_user(user_id="user-id-keycloak")

# Send User Action
response = keycloak_admin.send_update_account(user_id="user-id-keycloak", 
                                              payload=json.dumps(['UPDATE_PASSWORD']))

# Send Verify Email
response = keycloak_admin.send_verify_email(user_id="user-id-keycloak")

# Get sessions associated with the user
sessions = keycloak_admin.get_sessions(user_id="user-id-keycloak")

# Get themes, social providers, auth providers, and event listeners available on this server
server_info = keycloak_admin.get_server_info()

# Get clients belonging to the realm Returns a list of clients belonging to the realm
clients = keycloak_admin.get_clients()

# Get client - id (not client-id) from client by name
client_id=keycloak_admin.get_client_id("my-client")

# Get representation of the client - id of client (not client-id)
client = keycloak_admin.get_client(client_id=client_id)

# Get all roles for the client
client_roles = keycloak_admin.get_client_role(client_id=client_id)

# Create client role
keycloak_admin.create_client_role(client_id, "test")

# Get client role id from name
role_id = keycloak_admin.get_client_role_id(client_id=client_id, role_name="test")

# Get all roles for the realm or client
realm_roles = keycloak_admin.get_roles()

# Assign client role to user. Note that BOTH role_name and role_id appear to be required.
keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, role_id=role_id, role_name="test")
```
