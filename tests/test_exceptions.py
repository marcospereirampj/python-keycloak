"""Test the exceptions module."""

from unittest.mock import Mock

import pytest

from keycloak.exceptions import KeycloakOperationError, raise_error_from_response


def test_raise_error_from_response_from_dict():
    """Test raise error from response using a dictionary."""
    response = Mock()
    response.json.return_value = {"key": "value"}
    response.status_code = 408
    response.content = "Error"

    with pytest.raises(KeycloakOperationError):
        raise_error_from_response(
            response=response, error=dict(), expected_codes=[200], skip_exists=False,
        )
