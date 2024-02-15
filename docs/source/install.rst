.. _install:

Installation
========================

This part of the documentation covers the installation of Python-Keycloak. This is the first step to using the software library.

Via Pypi Package
-----------------

To install python-keycloak, run this command in your terminal of choice::

    pip install python-keycloak

Manually
-----------------

The python-keycloak code is `available <https://github.com/marcospereirampj/python-keycloak>`_. on Github.

You can either clone the public repository::

    git clone https://github.com/marcospereirampj/python-keycloak.git

Or, download the source code.

Once you have a copy of the source, you can embed it in your own Python package, or install it into your site-packages easily::

    python -m pip install .

Dependencies
-----------------

python-keycloak depends on:

- Python 3+
- `requests <https://requests.readthedocs.io>`_
- `python-jose <http://python-jose.readthedocs.io/en/latest/>`_
- `urllib3 <https://urllib3.readthedocs.io/en/stable/>`_


Tests Dependencies
-------------------

- `tox <https://tox.readthedocs.io/>`_
- `pytest <https://docs.pytest.org/en/latest/>`_
- `pytest-cov <https://github.com/pytest-dev/pytest-cov>`_
- `wheel <https://github.com/pypa/wheel>`_
