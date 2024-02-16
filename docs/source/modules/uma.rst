.. _uma:

UMA
========================


Configure client UMA
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


Create a resource set
-------------------------

.. code-block:: python

    resource_set = keycloak_uma.resource_set_create({
                    "name": "example_resource",
                    "scopes": ["example:read", "example:write"],
                    "type": "urn:example"})

List resource sets
-------------------------

.. code-block:: python

    resource_sets = uma.resource_set_list()

Get resource set
-------------------------

.. code-block:: python

    latest_resource = uma.resource_set_read(resource_set["_id"])

Update resource set
-------------------------

.. code-block:: python

    latest_resource["name"] = "New Resource Name"
    uma.resource_set_update(resource_set["_id"], latest_resource)

Delete resource set
------------------------
.. code-block:: python

    uma.resource_set_delete(resource_id=resource_set["_id"])
