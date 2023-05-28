# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Keycloak OpenID Connection Manager module.

The module contains mainly the implementation of KeycloakOpenIDConnection class.
This is an extension of the ConnectionManager class, and handles the automatic refresh
of openid tokens when required.
"""

from datetime import datetime, timedelta

from .connection import ConnectionManager
from .exceptions import KeycloakPostError
from .keycloak_openid import KeycloakOpenID


class KeycloakOpenIDConnection(ConnectionManager):
    """A class to help with OpenID connections which can auto refresh tokens.

    :param object: _description_
    :type object: _type_
    """

    _server_url = None
    _username = None
    _password = None
    _totp = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _connection = None
    _custom_headers = None
    _user_realm_name = None
    _expires_at = None

    def __init__(
        self,
        server_url,
        username=None,
        password=None,
        token=None,
        totp=None,
        realm_name="master",
        client_id="admin-cli",
        verify=True,
        client_secret_key=None,
        custom_headers=None,
        user_realm_name=None,
        timeout=60,
    ):
        """Init method.

        :param server_url: Keycloak server url
        :type server_url: str
        :param username: admin username
        :type username: str
        :param password: admin password
        :type password: str
        :param token: access and refresh tokens
        :type token: dict
        :param totp: Time based OTP
        :type totp: str
        :param realm_name: realm name
        :type realm_name: str
        :param client_id: client id
        :type client_id: str
        :param verify: True if want check connection SSL
        :type verify: bool
        :param client_secret_key: client secret key
            (optional, required only for access type confidential)
        :type client_secret_key: str
        :param custom_headers: dict of custom header to pass to each HTML request
        :type custom_headers: dict
        :param user_realm_name: The realm name of the user, if different from realm_name
        :type user_realm_name: str
        :param timeout: connection timeout in seconds
        :type timeout: int
        """
        # token is renewed when it hits 90% of its lifetime. This is to account for any possible
        # clock skew.
        self.token_lifetime_fraction = 0.9
        self.server_url = server_url
        self.username = username
        self.password = password
        self.token = token
        self.totp = totp
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.user_realm_name = user_realm_name
        self.timeout = timeout

        if self.token is None:
            self.get_token()

        self.headers = (
            {
                "Authorization": "Bearer " + self.token.get("access_token"),
                "Content-Type": "application/json",
            }
            if self.token is not None
            else {}
        )
        self.custom_headers = custom_headers

        super().__init__(
            base_url=self.server_url, headers=self.headers, timeout=60, verify=self.verify
        )

    @property
    def server_url(self):
        """Get server url.

        :returns: Keycloak server url
        :rtype: str
        """
        return self.base_url

    @server_url.setter
    def server_url(self, value):
        self.base_url = value

    @property
    def realm_name(self):
        """Get realm name.

        :returns: Realm name
        :rtype: str
        """
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def client_id(self):
        """Get client id.

        :returns: Client id
        :rtype: str
        """
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        """Get client secret key.

        :returns: Client secret key
        :rtype: str
        """
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def username(self):
        """Get username.

        :returns: Admin username
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        """Get password.

        :returns: Admin password
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def totp(self):
        """Get totp.

        :returns: TOTP
        :rtype: str
        """
        return self._totp

    @totp.setter
    def totp(self, value):
        self._totp = value

    @property
    def token(self):
        """Get token.

        :returns: Access and refresh token
        :rtype: dict
        """
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._expires_at = datetime.now() + timedelta(
            seconds=int(self.token_lifetime_fraction * self.token["expires_in"] if value else 0)
        )

    @property
    def expires_at(self):
        """Get token expiry time.

        :returns: Datetime at which the current token will expire
        :rtype: datetime
        """
        return self._expires_at

    @property
    def user_realm_name(self):
        """Get user realm name.

        :returns: User realm name
        :rtype: str
        """
        return self._user_realm_name

    @user_realm_name.setter
    def user_realm_name(self, value):
        self._user_realm_name = value

    @property
    def custom_headers(self):
        """Get custom headers.

        :returns: Custom headers
        :rtype: dict
        """
        return self._custom_headers

    @custom_headers.setter
    def custom_headers(self, value):
        self._custom_headers = value
        if self.custom_headers is not None:
            # merge custom headers to main headers
            self.headers.update(self.custom_headers)

    def get_token(self):
        """Get admin token.

        The admin token is then set in the `token` attribute.
        """
        if self.user_realm_name:
            token_realm_name = self.user_realm_name
        elif self.realm_name:
            token_realm_name = self.realm_name
        else:
            token_realm_name = "master"

        self.keycloak_openid = KeycloakOpenID(
            server_url=self.server_url,
            client_id=self.client_id,
            realm_name=token_realm_name,
            verify=self.verify,
            client_secret_key=self.client_secret_key,
            timeout=self.timeout,
        )

        grant_type = []
        if self.client_secret_key:
            grant_type.append("client_credentials")
        elif self.username and self.password:
            grant_type.append("password")

        if grant_type:
            self.token = self.keycloak_openid.token(
                self.username, self.password, grant_type=grant_type, totp=self.totp
            )
        else:
            self.token = None

    def refresh_token(self):
        """Refresh the token.

        :raises KeycloakPostError: In case the refresh token request failed.
        """
        refresh_token = self.token.get("refresh_token", None) if self.token else None
        if refresh_token is None:
            self.get_token()
        else:
            try:
                self.token = self.keycloak_openid.refresh_token(refresh_token)
            except KeycloakPostError as e:
                list_errors = [
                    b"Refresh token expired",
                    b"Token is not active",
                    b"Session not active",
                ]
                if e.response_code == 400 and any(err in e.response_body for err in list_errors):
                    self.get_token()
                else:
                    raise

        self.add_param_headers("Authorization", "Bearer " + self.token.get("access_token"))

    def _refresh_if_required(self):
        if datetime.now() >= self.expires_at:
            self.refresh_token()

    def raw_get(self, *args, **kwargs):
        """Call connection.raw_get.

        If auto_refresh is set for *get* and *access_token* is expired, it will refresh the token
        and try *get* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_get(*args, **kwargs)
        return r

    def raw_post(self, *args, **kwargs):
        """Call connection.raw_post.

        If auto_refresh is set for *post* and *access_token* is expired, it will refresh the token
        and try *post* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_post(*args, **kwargs)
        return r

    def raw_put(self, *args, **kwargs):
        """Call connection.raw_put.

        If auto_refresh is set for *put* and *access_token* is expired, it will refresh the token
        and try *put* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_put(*args, **kwargs)
        return r

    def raw_delete(self, *args, **kwargs):
        """Call connection.raw_delete.

        If auto_refresh is set for *delete* and *access_token* is expired,
        it will refresh the token and try *delete* once more.

        :param args: Additional arguments
        :type args: tuple
        :param kwargs: Additional keyword arguments
        :type kwargs: dict
        :returns: Response
        :rtype: Response
        """
        self._refresh_if_required()
        r = super().raw_delete(*args, **kwargs)
        return r
