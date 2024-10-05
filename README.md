[![CircleCI](https://github.com/marcospereirampj/python-keycloak/actions/workflows/daily.yaml/badge.svg)](https://github.com/marcospereirampj/python-keycloak/)
[![Documentation Status](https://readthedocs.org/projects/python-keycloak/badge/?version=latest)](http://python-keycloak.readthedocs.io/en/latest/?badge=latest)

# Python Keycloak

**python-keycloak** is a Python package providing access to the Keycloak API.

## Installation

Install via PyPI:

`$ pip install python-keycloak`

## Bug reports

Please report bugs and feature requests at
https://github.com/marcospereirampj/python-keycloak/issues

## Documentation

The documentation for python-keycloak is available on [readthedocs](http://python-keycloak.readthedocs.io).

## Keycloak version support

The library strives to always support Keycloak's latest version. Additionally to that, we also support 5 latest major versions of Keycloak,
in order to give our user base more time for smoother upgrades.

Current list of supported Keycloak versions:

- 26.X
- 25.X
- 24.X
- 23.X
- 22.X

## Python version support

We only support Python versions that have active or security support by the Python Software Foundation. You can find the list of active Python versions [here](https://endoflife.date/python).

## Example of Using Keycloak OpenID

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
```

## Example of Using Keycloak Admin API

```python
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
```

For more details, see the documentation available on [readthedocs](http://python-keycloak.readthedocs.io).
