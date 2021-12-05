#!/usr/bin/env bash

cat << EOF > /root/.pypirc
[distutils]
index-servers=pypi

[pypi]
username=${PYPI_USERNAME}
password=${PYPI_PASSWORD}
EOF

python setup.py sdist bdist_wheel --universal
twine upload dist/*
