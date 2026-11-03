"""Forge (project 2) — access follows Realliance SSO: teams and admin status sync at each sign-in, and
the two-step offboarding (SSO + Forgejo "prohibit login") blocks web, tokens and SSH, reversibly
(spec Success 3, 4; plan Task 8 + Review Focus 2, 3)."""
import os
import subprocess

import requests
import yaml

from conftest import REALM, admin_token, get, put
from forge_helpers import (FORGE, LUMA, forge_api, forge_login, forge_relogin, forge_signed_in, forge_token,
                           set_email, set_groups)


def _team_members(team):
    tid = next(t["id"] for t in forge_api("GET", "/api/v1/orgs/realliance/teams").json() if t["name"] == team)
    return {m["login"] for m in forge_api("GET", f"/api/v1/teams/{tid}/members").json()}


def test_team_follows_groups_at_signin(forge_user):  # Success 4
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    s = forge_login(u)
    assert u.name in _team_members("members")
    set_groups(u, ["/apps/forgejo", "/realliance-maintainers"])
    forge_relogin(s, u)
    assert u.name in _team_members("maintainers") and u.name not in _team_members("members")


def test_access_without_community_group_gets_no_team(forge_user):  # Review Focus 3
    u = forge_user()
    forge_login(u)
    assert all(u.name not in _team_members(t) for t in ("members", "maintainers", "Owners"))
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is False


def test_admin_status_dropped_at_next_signin(forge_user):
    u = forge_user(groups=("/apps/forgejo", "/forgejo-admins"))
    s = forge_login(u)
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is True
    set_groups(u, ["/apps/forgejo"])
    forge_relogin(s, u)
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is False


def test_team_map_not_in_public_config():
    """Since 2026-11-03 the SSO login source (and its group->team map) lives only in Forgejo's DB:
    the chart must not re-apply it (Forgejo refused to start while the SSO was down), and a team
    map in this public repo would leak hidden org names. forge-bot's private teams.yaml replaces it."""
    text = (LUMA / "cluster/applications/forgejo-release.yaml").read_text()
    app = yaml.safe_load(text)
    assert app["spec"]["source"]["helm"]["valuesObject"]["gitea"]["oauth"] == []
    applied = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "groupTeamMap" not in applied and "group-team-map" not in applied


def test_email_change_keeps_account(forge_user):  # Review Focus 2
    u = forge_user()
    s = forge_login(u)
    acct = forge_api("GET", f"/api/v1/users/{u.name}").json()  # login_name = the OIDC subject (stable)
    set_email(u, f"{u.name}-new@example.invalid")
    forge_relogin(s, u)
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["id"] == acct["id"]
    same_sub = forge_api("GET", "/api/v1/admin/users",
                         params={"source_id": acct["source_id"], "login_name": acct["login_name"]}).json()
    assert [a["login"] for a in same_sub] == [u.name]


def _set_kc_enabled(user, enabled):
    token = admin_token()
    rep = get(f"/admin/realms/{REALM}/users/{user.id}", token).json()
    rep["enabled"] = enabled
    assert put(f"/admin/realms/{REALM}/users/{user.id}", token, rep).status_code == 204


def _prohibit_login(user, prohibited):
    acct = forge_api("GET", f"/api/v1/users/{user.name}").json()
    r = forge_api("PATCH", f"/api/v1/admin/users/{user.name}",
                  json={"prohibit_login": prohibited, "login_name": acct["login_name"], "source_id": acct["source_id"]})
    assert r.status_code == 200, r.text


def test_offboarding_blocks_web_token_and_ssh_and_is_reversible(forge_user, tmp_path):  # Success 3
    u = forge_user()
    s = forge_login(u)
    token = forge_token(s, "offboarding", ["read:user", "write:repository"])
    repo = f"off-{os.urandom(3).hex()}"
    assert forge_api("POST", "/api/v1/user/repos", sudo=u.name,
                     json={"name": repo, "private": True, "auto_init": True}).status_code == 201
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "k")], check=True)
    pub = (tmp_path / "k.pub").read_text().strip()
    assert forge_api("POST", f"/api/v1/admin/users/{u.name}/keys", json={"title": "t", "key": pub}).status_code == 201
    env = dict(os.environ, GIT_SSH_COMMAND=f"ssh -i {tmp_path}/k -o IdentitiesOnly=yes -o BatchMode=yes "
               f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={tmp_path}/kh",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")  # no URL rewrites or credential helpers

    def web():
        return forge_signed_in(s)

    def api():
        return requests.get(f"{FORGE}/api/v1/user", headers={"Authorization": f"token {token}"}, timeout=20).status_code == 200

    def ssh():
        return subprocess.run(["git", "ls-remote", f"git@git.realliance.net:{u.name}/{repo}.git"], env=env,
                              capture_output=True, timeout=60).returncode == 0

    assert (web(), api(), ssh()) == (True, True, True)
    _set_kc_enabled(u, False)          # step 1: sso-people active: false
    _prohibit_login(u, True)           # step 2: Forgejo "prohibit login"
    assert (web(), api(), ssh()) == (False, False, False)
    _prohibit_login(u, False)
    _set_kc_enabled(u, True)
    s = forge_login(u)
    assert (web(), api(), ssh()) == (True, True, True)


def test_demotion_needs_the_forgejo_side_step(forge_user):  # final review, Important 4 (runbook)
    """Groups sync only at sign-in, so an SSO demotion alone leaves admin/team in place; the runbook's
    second step (undo it in Forgejo) sticks, because the next sign-in agrees with it."""
    u = forge_user(groups=("/apps/forgejo", "/forgejo-admins", "/realliance"))
    s = forge_login(u)
    acct = forge_api("GET", f"/api/v1/users/{u.name}").json()
    assert acct["is_admin"] is True and u.name in _team_members("members")
    set_groups(u, ["/apps/forgejo"])                                  # step 1: sso-people
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is True   # lingers
    assert u.name in _team_members("members")
    r = forge_api("PATCH", f"/api/v1/admin/users/{u.name}",          # step 2: Forgejo
                  json={"admin": False, "login_name": acct["login_name"], "source_id": acct["source_id"]})
    assert r.status_code == 200, r.text
    tid = next(t["id"] for t in forge_api("GET", "/api/v1/orgs/realliance/teams").json() if t["name"] == "members")
    assert forge_api("DELETE", f"/api/v1/teams/{tid}/members/{u.name}").status_code == 204
    forge_relogin(s, u)
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is False
    assert u.name not in _team_members("members")
