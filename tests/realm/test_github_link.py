"""Link GitHub: a link-only identity provider. It proves a person's GitHub username on their account
page; it is never a way to sign in or create an account."""
from conftest import REALM, SSO, admin_token, get

import requests


def _idp():
    r = get(f"/admin/realms/{REALM}/identity-provider/instances/github", admin_token())
    assert r.status_code == 200, "no github identity provider"
    return r.json()


def test_github_is_link_only():
    idp = _idp()
    assert idp["providerId"] == "github" and idp["enabled"] is True
    assert idp["linkOnly"] is True
    assert idp.get("hideOnLogin") is True or idp["config"].get("hideOnLoginPage") == "true"
    assert idp["trustEmail"] is False and idp["storeToken"] is False


def test_github_not_offered_on_the_sign_in_page():
    page = requests.get(f"{SSO}/realms/{REALM}/protocol/openid-connect/auth", timeout=20, params={
        "client_id": "account-console", "response_type": "code", "scope": "openid",
        "redirect_uri": f"{SSO}/realms/{REALM}/account/"}).text
    assert "broker/github" not in page and "social-github" not in page
