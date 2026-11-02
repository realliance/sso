"""Task 11 — groups, the groups claim, and the app module's default deny."""
import subprocess

from conftest import (REPO, create_group, decode, delete_group, flow_executions, password_grant,
                      realm_get)


def _direct_grant(client, u):
    return password_grant("realliance", client, u.name, u.pw)


def test_user_without_role_denied(acceptance_clients, user_factory):
    u = user_factory(groups=["/realliance"])
    r = _direct_grant("acceptance-tests", u)
    # deny-access-authenticator answers 401 with an HTML error page, never a token
    assert r.status_code == 401 and "access_token" not in r.text


def test_user_with_access_group_gets_token(acceptance_clients, user_factory):
    u = user_factory(groups=["/apps/acceptance-tests"])
    assert _direct_grant("acceptance-tests", u).status_code == 200


def test_groups_claim_flat_array(acceptance_clients, user_factory):
    u = user_factory(groups=["/apps/acceptance-tests", "/realliance"])
    claims = decode(_direct_grant("acceptance-tests", u).json()["id_token"])
    assert sorted(claims["groups"]) == ["acceptance-tests", "realliance"]


def test_no_groups_claim_without_scope(acceptance_clients, user_factory):
    u = user_factory(groups=["/apps/acceptance-tests-noscope", "/realliance"])
    claims = decode(_direct_grant("acceptance-tests-noscope", u).json()["id_token"])
    assert "groups" not in claims


def test_groups_scope_not_realm_default():
    assert "groups" not in [s["name"] for s in realm_get("/default-default-client-scopes")]


def test_community_groups_exist():
    names = {g["name"] for g in realm_get("/groups")}
    assert {"realmic", "realliance", "apps"} <= names


def test_app_browser_flow_denies_without_role():
    from conftest import client_by_id, flow_id
    c = client_by_id("acceptance-tests")
    assert c["authenticationFlowBindingOverrides"]["browser"] == flow_id("acceptance-tests-browser")
    ex = flow_executions("acceptance-tests-browser")
    cond = [e for e in ex if e.get("providerId") == "conditional-user-role"]
    assert len(cond) == 1 and any(e.get("providerId") == "deny-access-authenticator" for e in ex)


def test_console_group_untouched_by_tofu():
    gid = create_group("hidden-test-project")
    try:
        r = subprocess.run(["bash", "-c", "set -a; . ~/Repos/realliance-sso-secrets/realm/secrets.env; set +a; "
                            "tofu -chdir=realm plan -detailed-exitcode -input=false -no-color >/dev/null"],
                           cwd=REPO)
        assert r.returncode == 0
    finally:
        delete_group(gid)
