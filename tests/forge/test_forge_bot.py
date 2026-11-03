"""Forge bot accounts — forge-bot (site admin) and forge-ci (not admin) are local Forgejo accounts, and
forge-bot's API token carries admin scopes but cannot create repositories."""
from conftest import _load_env
from forge_helpers import FORGE_SECRETS, forge_api


def test_bot_accounts_are_local():
    for login, admin in (("forge-bot", True), ("forge-ci", False)):
        a = forge_api("GET", f"/api/v1/users/{login}").json()
        assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, admin, False)


def test_forge_bot_token_scopes():
    tok = _load_env(FORGE_SECRETS)["FORGE_BOT_FORGEJO_TOKEN"]
    assert forge_api("GET", "/api/v1/admin/users", token=tok, params={"limit": 1}).status_code == 200
    assert forge_api("POST", "/api/v1/user/repos", token=tok, json={"name": "nope"}).status_code == 403
