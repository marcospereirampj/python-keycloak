"""

"""

import json

from keycloak.exceptions import raise_error_from_response, KeycloakGetError
from .connection import ConnectionManager
from .urls_patterns import URL_WELL_KNOWN


class Keycloak:

    def __init__(self, server_url, client_id, realm_name, client_secret_key=None):
        self.__client_id = client_id
        self.__client_secret_key = client_secret_key
        self.__realm_name = realm_name

        self.__connection = ConnectionManager(base_url=server_url,
                                              headers={},
                                              timeout=60)

    def get_well_know(self):
        params = {"realm-name": self.__realm_name}
        data_raw = self.__connection.raw_get(URL_WELL_KNOWN.format(**params))
        raise_error_from_response(data_raw, KeycloakGetError)
        return json.loads(data_raw.text)

    def auth(self):
        """

        http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

        :return:
        """
