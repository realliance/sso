"""Forge (project 2) — the realm side: the forgejo client and its groups."""
from conftest import client_by_id, flow_id, group_id, realm_get


def test_forgejo_client_confidential_with_exact_redirect():
    c = client_by_id("forgejo")
    assert c["publicClient"] is False and c["standardFlowEnabled"] is True
    assert c["directAccessGrantsEnabled"] is False
    assert c["redirectUris"] == ["https://git.realliance.net/user/oauth2/realliance/callback"]


def test_forgejo_client_gets_groups_scope():
    assert "groups" in client_by_id("forgejo")["defaultClientScopes"]


def test_forge_groups_exist():
    names = {g["name"] for g in realm_get("/groups")}
    assert {"forgejo-admins", "realliance-maintainers"} <= names
    assert group_id("/apps/forgejo")


def test_forgejo_flow_denies_without_role():
    assert client_by_id("forgejo")["authenticationFlowBindingOverrides"]["browser"] == flow_id("forgejo-browser")


def test_forgejo_listed_in_account_console():
    c = client_by_id("forgejo")
    assert c["baseUrl"] == "https://git.realliance.net" and c["alwaysDisplayInConsole"] is True
