.. python-keycloak documentation master file, created by
   sphinx-quickstart on Tue Aug 15 11:02:59 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. image:: https://travis-ci.org/marcospereirampj/python-keycloak.svg?branch=master
    :target: https://travis-ci.org/marcospereirampj/python-keycloak

.. image:: https://readthedocs.org/projects/python-keycloak/badge/?version=latest
    :target: http://python-keycloak.readthedocs.io/en/latest/?badge=latest


Welcome to python-keycloak's documentation!
===========================================

**python-keycloak** is a Python package providing access to the Keycloak API.

Installation
==================

Via Pypi Package::

   $ pip install python-keycloak

Manually::

   $ python setup.py install

Dependencies
==================

python-keycloak depends on:

* Python 3
* `requests <http://docs.python-requests.org/en/master/>`_

Tests Dependencies
------------------

* unittest
* `httmock <https://github.com/patrys/httmock>`_

Bug reports
==================

Please report bugs and feature requests at
`https://github.com/marcospereirampj/python-keycloak/issues <https://github.com/marcospereirampj/python-keycloak/issues>`_

Documentation
==================

The documentation for python-keycloak is available on `readthedocs <http://python-keycloak.readthedocs.io>`_.

Contributors
==================

* `Agriness Team <http://www.agriness.com/pt/>`_

Usage
=====

Main methods::

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

    # Instropect
    keycloak.instropect(token['access_token'], rpt['rpt'])

