"""Tests for PKCE flow: code verifier and code challenge handling."""

import re
import urllib.parse

import requests

from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.pkce_utils import generate_code_challenge, generate_code_verifier


def test_pkce_auth_url_and_token(env: object, admin: KeycloakAdmin) -> None:
    """Test PKCE flow: auth_url includes code_challenge, token includes code_verifier."""
    client_representation = {
        "clientId": "pkce-test",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "implicitFlowEnabled": False,
        "redirectUris": ["http://test.test/callback"],
        "webOrigins": ["*"],
    }
    admin.create_client(client_representation)

    oid = KeycloakOpenID(
        server_url=f"http://{env.keycloak_host}:{env.keycloak_port}",
        realm_name="master",
        client_id="pkce-test",
    )
    code_verifier = generate_code_verifier()
    code_challenge, code_challenge_method = generate_code_challenge(code_verifier)

    # Build PKCE auth URL
    url = oid.auth_url(
        redirect_uri="http://test.test/callback",
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope="openid%20email",
    )
    assert f"code_challenge={code_challenge}" in url
    assert f"code_challenge_method={code_challenge_method}" in url

    session = requests.Session()
    resp = session.get(url, allow_redirects=False)
    cookies = resp.cookies.get_dict()
    assert resp.status_code == 200
    resp_url = re.findall(r"action=\"(.*)\" method", resp.text)[0]
    resp = session.post(
        resp_url,
        data={"username": env.keycloak_admin, "password": env.keycloak_admin_password},
        allow_redirects=False,
        cookies=cookies,
    )
    assert resp.status_code == 302, resp.text
    resp_code = urllib.parse.parse_qs(resp.headers["Location"])["code"][0]

    access_token = oid.token(
        grant_type="authorization_code",
        code=resp_code,
        redirect_uri="http://test.test/callback",
        code_verifier=code_verifier,
    )
    info = oid.userinfo(access_token["access_token"])
    assert info["preferred_username"] == env.keycloak_admin
