# -*- coding: utf-8 -*-
import re

from setuptools import find_packages, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    reqs = fh.read().split("\n")

with open("dev-requirements.txt", "r") as fh:
    dev_reqs = fh.read().split("\n")

with open("docs-requirements.txt", "r") as fh:
    docs_reqs = fh.read().split("\n")


VERSIONFILE = "src/keycloak/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
    name="python-keycloak",
    version=verstr,
    url="https://github.com/marcospereirampj/python-keycloak",
    license="The MIT License",
    author="Marcos Pereira, Richard Nemeth",
    author_email="marcospereira.mpj@gmail.com, ryshoooo@gmail.com",
    keywords="keycloak openid oidc",
    description="python-keycloak is a Python package providing access to the Keycloak API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=reqs,
    tests_require=dev_reqs,
    extras_require={"docs": docs_reqs},
    python_requires=">=3.7",
    project_urls={
        "Documentation": "https://python-keycloak.readthedocs.io/en/latest/",
        "Issue tracker": "https://github.com/marcospereirampj/python-keycloak/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 3 - Alpha",
        "Operating System :: MacOS",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Utilities",
    ],
)
