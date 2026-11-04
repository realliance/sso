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
