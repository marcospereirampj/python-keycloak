.. _openid_client:


OpenID Client
========================

Configure client OpenID
-------------------------

.. code-block:: python

    from keycloak import KeycloakOpenID

    # Configure client
    # For KeyCloak 17+ the server url must be something like "http://localhost:8080" without "/auth"
    keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                     client_id="example_client",
                                     realm_name="example_realm",
                                     client_secret_key="secret")


Get .well_know
-----------------------

.. code-block:: python

    config_well_known = keycloak_openid.well_known()


Get code with OAuth authorization request
----------------------------------------------

.. code-block:: python

    auth_url = keycloak_openid.auth_url(
        redirect_uri="your_call_back_url",
        scope="email",
        state="your_state_info")


Get access token with code
----------------------------------------------

.. code-block:: python

    access_token = keycloak_openid.token(
        grant_type='authorization_code',
        code='the_code_you_get_from_auth_url_callback',
        redirect_uri="your_call_back_url")


Get access token with user and password
----------------------------------------------

.. code-block:: python

    token = keycloak_openid.token("user", "password")
    token = keycloak_openid.token("user", "password", totp="012345")


Get token using Token Exchange
----------------------------------------------

.. code-block:: python

    token = keycloak_openid.exchange_token(token['access_token'],
                "my_client", "other_client", "some_user")


Refresh token
----------------------------------------------

.. code-block:: python

    token = keycloak_openid.refresh_token(token['refresh_token'])

Get UserInfo
----------------------------------------------

.. code-block:: python

    userinfo = keycloak_openid.userinfo(token['access_token'])

Logout
----------------------------------------------

.. code-block:: python

    keycloak_openid.logout(token['refresh_token'])

Get certs
----------------------------------------------

.. code-block:: python

    certs = keycloak_openid.certs()

Introspect RPT
----------------------------------------------

.. code-block:: python

    token_rpt_info = keycloak_openid.introspect(keycloak_openid.introspect(token['access_token'],
                                                                           rpt=rpt['rpt'],
                                                                           token_type_hint="requesting_party_token"))

Introspect token
----------------------------------------------

.. code-block:: python

    token_info = keycloak_openid.introspect(token['access_token'])


Decode token
----------------------------------------------

.. code-block:: python

    token_info = keycloak_openid.decode_token(token['access_token'])
    # Without validation
    token_info = keycloak_openid.decode_token(token['access_token'], validate=False)


Get UMA-permissions by token
----------------------------------------------

.. code-block:: python

    token = keycloak_openid.token("user", "password")
    permissions = keycloak_openid.uma_permissions(token['access_token'])

Get UMA-permissions by token with specific resource and scope requested
--------------------------------------------------------------------------

.. code-block:: python

    token = keycloak_openid.token("user", "password")
    permissions = keycloak_openid.uma_permissions(token['access_token'], permissions="Resource#Scope")

Get auth status for a specific resource and scope by token
--------------------------------------------------------------------------

.. code-block:: python

    token = keycloak_openid.token("user", "password")
    auth_status = keycloak_openid.has_uma_access(token['access_token'], "Resource#Scope")
