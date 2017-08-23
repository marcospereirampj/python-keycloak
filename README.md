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

## Usage

```python
from keycloak import Keycloak

# Configure client
keycloak = Keycloak(server_url="http://localhost:8080/auth/",
                    client_id="example_client",
                    realm_name="example_realm",
                    client_secret_key="secret")

# Get WellKnow
config_well_know = keycloak.well_know()

# Get Token
token = keycloak.token("user", "password")

# Get Userinfo
userinfo = keycloak.userinfo(token['access_token'])

# Logout
keycloak.logout(token['refresh_token'])

# Get Certs
certs = keycloak.certs()

# Get RPT (Entitlement)
token = keycloak.token("user", "password")
rpt = keycloak.entitlement(token['access_token'], "resource_id")

# Instropect RPT
token_rpt_info = keycloak.instropect(keycloak.instropect(token['access_token'], rpt=rpt['rpt'],
                                     token_type_hint="requesting_party_token"))

# Instropect Token
token_info = keycloak.instropect(token['access_token']))

# Decode Token
KEYCLOAK_PUBLIC_KEY = "secret"
options = {"verify_signature": True, "verify_aud": True, "exp": True}
token_info = keycloak.decode_token(token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)

# Get permissions by token
token = keycloak.token("user", "password")
keycloak.load_authorization_config("example-authz-config.json")
policies = keycloak.get_policies(token['access_token'])
permissions = keycloak.get_permissions(token['access_token'])

```