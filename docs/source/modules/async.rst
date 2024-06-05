.. admin:

Use Python Keycloak Asynchronously
========================

Asynchronous admin client
-------------------------

Configure admin client
-------------------------

.. code-block:: python


    admin = KeycloakAdmin(
                server_url="http://localhost:8080/",
                username='example-admin',
                password='secret',
                realm_name="master",
                user_realm_name="only_if_other_realm_than_master")


Configure admin client with connection
--------------------------------------------------

.. code-block:: python

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


Create user asynchronously
-------------------------

.. code-block:: python

    new_user = await keycloak_admin.a_create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example"})


Add user asynchronously and raise exception if username already exists
-----------------------------------------------------------

The exist_ok currently defaults to True for backwards compatibility reasons.

.. code-block:: python

    new_user = await keycloak_admin.a_create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example"},
                                            exist_ok=False)

Add user asynchronously and set password
---------------------------

.. code-block:: python

    new_user = await keycloak_admin.a_create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example",
                                            "credentials": [{"value": "secret","type": "password",}]})


Add user asynchronous and specify a locale
------------------------------

.. code-block:: python

    new_user = await keycloak_admin.a_create_user({"email": "example@example.fr",
                                           "username": "example@example.fr",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example",
                                           "attributes": {
                                               "locale": ["fr"]
                                           }})

Asynchronous User counter
------------------------------

.. code-block:: python

    count_users = await keycloak_admin.a_users_count()

Get users Returns a list of users asynchronously, filtered according to query parameters
----------------------------------------------------------------------------

.. code-block:: python

    users = await keycloak_admin.a_get_users({})

Get user ID asynchronously from username
------------------------------

.. code-block:: python

    user_id_keycloak = await keycloak_admin.a_get_user_id("username-keycloak")


Get user asynchronously
------------------------------

.. code-block:: python

    user = await keycloak_admin.a_get_user("user-id-keycloak")

Update user asynchronously
------------------------------

.. code-block:: python

    response = await keycloak_admin.a_update_user(user_id="user-id-keycloak",
                                          payload={'firstName': 'Example Update'})


Update user password asynchronously
------------------------------

.. code-block:: python

    response = await keycloak_admin.a_set_user_password(user_id="user-id-keycloak", password="secret", temporary=True)


Get user credentials asynchronously
------------------------------

.. code-block:: python

    credentials = await keycloak_admin.a_get_credentials(user_id='user_id')

Get user credential asynchronously by ID
------------------------------

.. code-block:: python

    credential = await keycloak_admin.a_get_credential(user_id='user_id', credential_id='credential_id')

Delete user credential asynchronously
------------------------------

.. code-block:: python

    response = await keycloak_admin.a_delete_credential(user_id='user_id', credential_id='credential_id')

Delete User asynchronously
------------------------------

.. code-block:: python

    response = await  keycloak_admin.a_delete_user(user_id="user-id-keycloak")

Get consents granted asynchronously by the user
--------------------------------

.. code-block:: python

    consents = await keycloak_admin.a_consents_user(user_id="user-id-keycloak")

Send user action asynchronously
------------------------------

.. code-block:: python

    response = await keycloak_admin.a_send_update_account(user_id="user-id-keycloak",
                                                  payload=['UPDATE_PASSWORD'])

Send verify email asynchronously
------------------------------

.. code-block:: python

    response = await keycloak_admin.a_send_verify_email(user_id="user-id-keycloak")

Get sessions associated asynchronously with the user
--------------------------------------

.. code-block:: python

    sessions = await keycloak_admin.a_get_sessions(user_id="user-id-keycloak")




Asynchronous OpenID Client
========================

Asynchronous Configure client OpenID
-------------------------

.. code-block:: python

    from keycloak import KeycloakOpenID

    # Configure client
    # For versions older than 18 /auth/ must be added at the end of the server_url.
    keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/",
                                     client_id="example_client",
                                     realm_name="example_realm",
                                     client_secret_key="secret")


Get .well_know asynchronously
-----------------------

.. code-block:: python

    config_well_known = await keycloak_openid.a_well_known()


Get code asynchronously with OAuth authorization request
----------------------------------------------

.. code-block:: python

    auth_url = await keycloak_openid.a_auth_url(
        redirect_uri="your_call_back_url",
        scope="email",
        state="your_state_info")


Get access token asynchronously with code
----------------------------------------------

.. code-block:: python

    access_token = await keycloak_openid.a_token(
        grant_type='authorization_code',
        code='the_code_you_get_from_auth_url_callback',
        redirect_uri="your_call_back_url")


Get access asynchronously token with user and password
----------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_token("user", "password")
    token = await keycloak_openid.a_token("user", "password", totp="012345")


Get token asynchronously using Token Exchange
----------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_exchange_token(token['access_token'],
                "my_client", "other_client", "some_user")


Refresh token asynchronously
----------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_refresh_token(token['refresh_token'])

Get UserInfo asynchronously
----------------------------------------------

.. code-block:: python

    userinfo = await keycloak_openid.a_userinfo(token['access_token'])

Logout asynchronously
----------------------------------------------

.. code-block:: python

    await keycloak_openid.a_logout(token['refresh_token'])

Get certs asynchronously
----------------------------------------------

.. code-block:: python

    certs = await keycloak_openid.a_certs()

Introspect RPT asynchronously
----------------------------------------------

.. code-block:: python

    token_rpt_info = await keycloak_openid.a_introspect(await keycloak_openid.a_introspect(token['access_token'],
                                                                           rpt=rpt['rpt'],
                                                                           token_type_hint="requesting_party_token"))

Introspect token asynchronously
----------------------------------------------

.. code-block:: python

    token_info = await keycloak_openid.a_introspect(token['access_token'])


Decode token asynchronously
----------------------------------------------

.. code-block:: python

    token_info = await keycloak_openid.a_decode_token(token['access_token'])
    # Without validation
    token_info = await keycloak_openid.a_decode_token(token['access_token'], validate=False)


Get UMA-permissions asynchronously by token
----------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_token("user", "password")
    permissions = await keycloak_openid.a_uma_permissions(token['access_token'])

Get UMA-permissions asynchronously by token with specific resource and scope requested
--------------------------------------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_token("user", "password")
    permissions = await keycloak_openid.a_uma_permissions(token['access_token'], permissions="Resource#Scope")

Get auth status asynchronously for a specific resource and scope by token
--------------------------------------------------------------------------

.. code-block:: python

    token = await keycloak_openid.a_token("user", "password")
    auth_status = await keycloak_openid.a_has_uma_access(token['access_token'], "Resource#Scope")




Asynchronous UMA
========================


Asynchronous Configure client UMA
-------------------------

.. code-block:: python

    from keycloak import KeycloakOpenIDConnection
    from keycloak import KeycloakUMA

    keycloak_connection = KeycloakOpenIDConnection(
                            server_url="http://localhost:8080/",
                            realm_name="master",
                            client_id="my_client",
                            client_secret_key="client-secret")

    keycloak_uma = KeycloakUMA(connection=keycloak_connection)


Create a resource set asynchronously
-------------------------

.. code-block:: python

    resource_set = await keycloak_uma.a_resource_set_create({
                    "name": "example_resource",
                    "scopes": ["example:read", "example:write"],
                    "type": "urn:example"})

List resource sets asynchronously
-------------------------

.. code-block:: python

    resource_sets = await uma.a_resource_set_list()

Get resource set asynchronously
-------------------------

.. code-block:: python

    latest_resource = await uma.a_resource_set_read(resource_set["_id"])

Update resource set asynchronously
-------------------------

.. code-block:: python

    latest_resource["name"] = "New Resource Name"
    await uma.a_resource_set_update(resource_set["_id"], latest_resource)

Delete resource set asynchronously
------------------------
.. code-block:: python

    await uma.a_resource_set_delete(resource_id=resource_set["_id"])
