#!/usr/bin/env bash

cat << EOF > /root/.pypirc
[distutils]
index-servers=pypi

[pypi]
repository=https://upload.pypi.org/legacy/
username=${PYPI_USERNAME}
password=${PYPI_PASSWORD}
EOF

python setup.py sdist upload -r pypi