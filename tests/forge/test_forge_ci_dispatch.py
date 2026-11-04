"""ci-dispatch — a local site-administrator account whose token carries exactly the scopes the dispatcher
needs: read the job queue and runners, mint runners, read repositories, users and orgs, and write nothing else."""
import secrets

from ci_helpers import EXPECTED_ADMINS, ci_token, forge_api_paged
from forge_helpers import FORGE_BOT_REPO, INVENTORY, forge_api, team_members


def test_ci_dispatch_account_local_admin():
    a = forge_api("GET", "/api/v1/users/ci-dispatch").json()
    assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, True, False)


def test_ci_dispatch_token_scopes():
    t = ci_token()
    r = forge_api("GET", "/api/v1/admin/actions/runners/jobs", token=t, params={"labels": "tiny"})
    assert r.status_code == 200
    r = forge_api("GET", "/api/v1/admin/actions/runners", token=t)
    assert r.status_code == 200
    r = forge_api("GET", f"/api/v1/repos/{INVENTORY}/branches/main", token=t)
    assert r.status_code == 200
    r = forge_api("GET", "/api/v1/users/forgejo-admin", token=t)
    assert r.status_code == 200
    # No write:repository. Scope checks run before body validation, so a 403 is the scope and a 422
    # would be a wrong scope; the empty body means a wrong scope still creates nothing.
    r = forge_api("POST", "/api/v1/user/repos", token=t, json={})
    assert r.status_code == 403


def test_ci_dispatch_token_cannot_write_repository():
    """A valid write against a throwaway repo this test creates and deletes (F29): never a real resource."""
    name = f"ci-scope-{secrets.token_hex(4)}"
    path = f"/api/v1/repos/forgejo-admin/{name}"
    made = forge_api("POST", "/api/v1/user/repos", json={"name": name, "private": True})
    assert made.status_code == 201
    try:
        r = forge_api("PATCH", path, token=ci_token(), json={"description": "scope probe"})
        assert r.status_code == 403
        after = forge_api("GET", path).json()
        assert after["description"] == ""
        r = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}", token=ci_token())
        assert r.status_code == 200          # read:repository does reach it
    finally:
        forge_api("DELETE", path)
    assert forge_api("GET", path).status_code == 404


def test_site_admins_as_expected():          # D19, the interim check
    admins = {u["login"] for u in forge_api_paged("/api/v1/admin/users") if u["is_admin"]}
    assert admins <= EXPECTED_ADMINS | team_members("realliance-ops", "Owners")


# realliance/ci-dispatch: declared in the inventory, shaped like forge-bot (runner classes plan Task 2).
CI_DISPATCH_REPO = "realliance/ci-dispatch"

def test_ci_dispatch_repo_public_and_protected():
    r = forge_api("GET", f"/api/v1/repos/{CI_DISPATCH_REPO}").json()
    assert (r["private"], r["has_actions"], r["has_packages"]) == (False, True, True)
    assert r["default_merge_style"] == "fast-forward-only"
    assert forge_api("GET", f"/api/v1/repos/{CI_DISPATCH_REPO}/branches/main").status_code == 200
    bp = forge_api("GET", f"/api/v1/repos/{CI_DISPATCH_REPO}/branch_protections/main").json()
    assert bp["enable_push"] is False and bp["require_signed_commits"] is True
    assert bp["enable_merge_whitelist"] is True and bp["enable_approvals_whitelist"] is True
    assert bp["merge_whitelist_teams"] == ["Owners"] and bp["approvals_whitelist_teams"] == ["Owners"]
    tags = forge_api("GET", f"/api/v1/repos/{CI_DISPATCH_REPO}/tag_protections").json()
    assert [(t["name_pattern"], t["whitelist_teams"]) for t in tags] == [("v*", ["Owners"])]


def test_ci_dispatch_registry_secret_exists():
    # REGISTRY_TOKEN is an org-level Actions secret (forge-bot has no repo-level one), so ci-dispatch
    # inherits it. Names only, never values.
    names = {s["name"] for s in forge_api("GET", "/api/v1/orgs/realliance/actions/secrets").json()}
    names |= {s["name"] for s in forge_api("GET", f"/api/v1/repos/{CI_DISPATCH_REPO}/actions/secrets").json()}
    assert "REGISTRY_TOKEN" in names


# The galaxy runner (luma-homeops cluster/forgejo-runner) holds one repo-scoped connection per allowlisted
# repo: forge-bot's, and from runner classes Task 5 ci-dispatch's (spec "Build"). Repo listings without
# `visible` leave out instance-scope runners (F15), so ephemeral ci-tiny-* runners never show here.
GALAXY_CONNECTIONS = {FORGE_BOT_REPO: "galaxy-forge-bot", CI_DISPATCH_REPO: "galaxy-ci-dispatch"}
NOT_ON_GALAXY = ("realliance/realliance.net", "realliance/brand", "realliance/pages", "realliance/forgejo")
WRITE = {"write", "admin", "owner"}


def _galaxy_rows(repo: str) -> list[dict]:
    r = forge_api("GET", f"/api/v1/repos/{repo}/actions/runners")
    r.raise_for_status()
    return [x for x in r.json() or [] if "galaxy" in {lbl.split(":")[0] for lbl in x["labels"]}]


def test_galaxy_serves_forge_bot_and_ci_dispatch_only():
    for repo, name in GALAXY_CONNECTIONS.items():
        repo_id = forge_api("GET", f"/api/v1/repos/{repo}").json()["id"]
        rows = [(x["name"], x["repo_id"], sorted(x["labels"])) for x in _galaxy_rows(repo)]
        assert rows == [(name, repo_id, ["galaxy"])], f"{repo}: {rows}"   # one row: a rotated-out one is gone
    for repo in NOT_ON_GALAXY:
        assert [x["name"] for x in _galaxy_rows(repo)] == [], f"{repo} has a galaxy runner"


def _writers(repo: str) -> tuple[set[str], set[str]]:
    """(teams, collaborators) that can push to `repo` or run its Actions: a branch push starts a galaxy run."""
    def can_write(t: dict) -> bool:
        units = t.get("units_map") or {}
        return t["permission"] in WRITE or any(units.get(u) in WRITE for u in ("repo.code", "repo.actions"))
    teams = {t["name"] for t in forge_api_paged(f"/api/v1/repos/{repo}/teams") if can_write(t)}
    collaborators = set()
    for c in forge_api_paged(f"/api/v1/repos/{repo}/collaborators"):
        p = forge_api("GET", f"/api/v1/repos/{repo}/collaborators/{c['login']}/permission")
        p.raise_for_status()
        if p.json()["permission"] in WRITE:
            collaborators.add(c["login"])
    return teams, collaborators


def test_ci_dispatch_and_forge_bot_write_access_equal():
    # The premise for sharing one runner pod (spec "Build"): whoever can push a branch to ci-dispatch can
    # already push one to forge-bot, and the reverse. Both repos live in the same org, so equal team names
    # are equal people.
    bot, ci = _writers(FORGE_BOT_REPO), _writers(CI_DISPATCH_REPO)
    assert "Owners" in bot[0]          # positive control: the listing does see team access
    assert bot == ci, f"forge-bot {bot} vs ci-dispatch {ci}"
