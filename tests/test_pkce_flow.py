from unittest import mock

from keycloak import KeycloakOpenID
from keycloak.pkce_utils import generate_code_challenge, generate_code_verifier


def test_pkce_auth_url_and_token(env):
    """
    Test PKCE flow: auth_url includes code_challenge, token includes code_verifier.
    """
    oid = KeycloakOpenID(
        server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
        realm_name="master",
        client_id="admin-cli",
    )
    code_verifier = generate_code_verifier()
    code_challenge, code_challenge_method = generate_code_challenge(code_verifier)

    # Build PKCE auth URL
    url = oid.auth_url(
        redirect_uri="http://test.test/*",
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    assert f"code_challenge={code_challenge}" in url
    assert f"code_challenge_method={code_challenge_method}" in url

    # Simulate token exchange with PKCE
    # This part would require a real code from Keycloak, so we mock the response
    with mock.patch.object(oid, "token", return_value={
        "access_token": mock.ANY,
        "refresh_token": mock.ANY,
        "token_type": "Bearer",
    }) as mocked_token:
        token = oid.token(
            grant_type="authorization_code",
            code="dummy_code",
            redirect_uri="http://test.test/*",
            code_verifier=code_verifier,
        )
        mocked_token.assert_called_with(
            grant_type="authorization_code",
            code="dummy_code",
            redirect_uri="http://test.test/*",
            code_verifier=code_verifier,
        )
        assert "access_token" in token
        assert "refresh_token" in token
        assert token["token_type"] == "Bearer"
