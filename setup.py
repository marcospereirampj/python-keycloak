# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='python-keycloak',
    version='0.12.1',
    url='https://bitbucket.org/agriness/python-keycloak',
    license='GNU General Public License - V3',
    author='Marcos Pereira',
    author_email='marcospereira.mpj@gmail.com',
    keywords='keycloak openid',
    description=u'python-keycloak is a Python package providing access to the Keycloak API.',
    packages=['keycloak', 'keycloak.authorization', 'keycloak.tests'],
    install_requires=['requests==2.18.4', 'httmock==1.2.5', 'python-jose==1.4.0', 'simplejson'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 3 - Alpha',
        'Operating System :: MacOS',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Utilities'
    ]
)
