.. admin:

Admin Client
========================


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


Create user
-------------------------

.. code-block:: python

    new_user = keycloak_admin.create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example"})


Add user and raise exception if username already exists
-----------------------------------------------------------

The exist_ok currently defaults to True for backwards compatibility reasons.

.. code-block:: python

    new_user = keycloak_admin.create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example"},
                                            exist_ok=False)

Add user and set password
---------------------------

.. code-block:: python

    new_user = keycloak_admin.create_user({"email": "example@example.com",
                                           "username": "example@example.com",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example",
                                            "credentials": [{"value": "secret","type": "password",}]})


Add user and specify a locale
------------------------------

.. code-block:: python

    new_user = keycloak_admin.create_user({"email": "example@example.fr",
                                           "username": "example@example.fr",
                                           "enabled": True,
                                           "firstName": "Example",
                                           "lastName": "Example",
                                           "attributes": {
                                               "locale": ["fr"]
                                           }})

User counter
------------------------------

.. code-block:: python

    count_users = keycloak_admin.users_count()

Get users Returns a list of users, filtered according to query parameters
----------------------------------------------------------------------------

.. code-block:: python

    users = keycloak_admin.get_users({})

Get user ID from username
------------------------------

.. code-block:: python

    user_id_keycloak = keycloak_admin.get_user_id("username-keycloak")


Get user
------------------------------

.. code-block:: python

    user = keycloak_admin.get_user("user-id-keycloak")

Update user
------------------------------

.. code-block:: python

    response = keycloak_admin.update_user(user_id="user-id-keycloak",
                                          payload={'firstName': 'Example Update'})


Update user password
------------------------------

.. code-block:: python

    response = keycloak_admin.set_user_password(user_id="user-id-keycloak", password="secret", temporary=True)


Get user credentials
------------------------------

.. code-block:: python

    credentials = keycloak_admin.get_credentials(user_id='user_id')

Get user credential by ID
------------------------------

.. code-block:: python

    credential = keycloak_admin.get_credential(user_id='user_id', credential_id='credential_id')

Delete user credential
------------------------------

.. code-block:: python

    response = keycloak_admin.delete_credential(user_id='user_id', credential_id='credential_id')

Delete User
------------------------------

.. code-block:: python

    response = keycloak_admin.delete_user(user_id="user-id-keycloak")

Get consents granted by the user
--------------------------------

.. code-block:: python

    consents = keycloak_admin.consents_user(user_id="user-id-keycloak")

Send user action
------------------------------

.. code-block:: python

    response = keycloak_admin.send_update_account(user_id="user-id-keycloak",
                                                  payload=['UPDATE_PASSWORD'])

Send verify email
------------------------------

.. code-block:: python

    response = keycloak_admin.send_verify_email(user_id="user-id-keycloak")

Get sessions associated with the user
--------------------------------------

.. code-block:: python

    sessions = keycloak_admin.get_sessions(user_id="user-id-keycloak")
