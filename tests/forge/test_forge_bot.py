"""Forge bot accounts: forge-bot (site admin) is a local Forgejo account whose API token carries admin scopes but
cannot create repositories. forge-ci is retired (2026-11-04): login prohibited, in no team."""
from conftest import _load_env
from forge_helpers import FORGE_SECRETS, forge_api


def test_bot_accounts_are_local():
    a = forge_api("GET", "/api/v1/users/forge-bot").json()
    assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, True, False)


def test_forge_ci_is_retired():
    a = forge_api("GET", "/api/v1/users/forge-ci").json()
    assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, False, True)
    assert forge_api("GET", "/api/v1/user/teams", sudo="forge-ci").json() == []


def test_forge_bot_token_scopes():
    tok = _load_env(FORGE_SECRETS)["FORGE_BOT_FORGEJO_TOKEN"]
    listing = forge_api("GET", "/api/v1/admin/users", token=tok, params={"limit": 1})
    assert listing.status_code == 200
    create = forge_api("POST", "/api/v1/user/repos", token=tok, json={"name": "nope"})
    assert create.status_code == 403
