"""The user_factory teardown removes the forge account (and its repos) a sign-in created."""
import secrets

from conftest import REALM, _teardown_users, admin_token, get
from forge_helpers import forge_api, forge_login


def test_teardown_purges_forge_account_and_keycloak_user(forge_user):
    u = forge_user()
    forge_login(u)
    repo = f"demo-{secrets.token_hex(3)}"
    r = forge_api("POST", "/api/v1/user/repos", sudo=u.name, json={"name": repo})
    assert r.status_code == 201
    assert forge_api("GET", f"/api/v1/repos/{u.name}/{repo}").status_code == 200

    failures = _teardown_users([u])  # what the fixture runs after the test

    assert failures == []
    assert forge_api("GET", f"/api/v1/users/{u.name}").status_code == 404
    assert forge_api("GET", f"/api/v1/repos/{u.name}/{repo}").status_code == 404
    kc_status = get(f"/admin/realms/{REALM}/users/{u.id}", admin_token()).status_code
    assert kc_status == 404
    # a second run is clean: 404 on both sides is fine
    assert _teardown_users([u]) == []
