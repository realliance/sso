"""Forge: the docs site repositories (docs-site plan Task 2). realliance/docs is the public site source,
declared by the inventory so that its main rule is the review gate for what goes live; realliance-ops/docs-deploy
is the Owners-only deploy job. The tag rule and apply_to_admins are API-only settings (the provider has no
resource for either), so these tests are what holds them."""
from forge_helpers import DOCS_DEPLOY_REPO, DOCS_REPO, forge_api

# Forgejo names a job's status "<workflow> / <job> (<event>)"; Task 1 observed both on a real PR.
CONTEXTS = ["site / vale (pull_request)", "site / build (pull_request)"]
DOCS_APPROVALS = 0   # R1 = C: 0 until launch; the launch task raises it to 1


def test_docs_repo_public_and_protected():
    r = forge_api("GET", f"/api/v1/repos/{DOCS_REPO}").json()
    assert (r["private"], r["has_actions"], r["has_packages"]) == (False, True, False)
    assert r["default_merge_style"] == "squash"
    assert r["allow_squash_merge"] is True and r["allow_fast_forward_only_merge"] is True
    assert r["allow_merge_commits"] is False and r["allow_rebase"] is False and r["allow_rebase_explicit"] is False
    assert forge_api("GET", f"/api/v1/repos/{DOCS_REPO}/branches/main").status_code == 200
    bp = forge_api("GET", f"/api/v1/repos/{DOCS_REPO}/branch_protections/main").json()
    assert bp["enable_push"] is False
    assert bp["required_approvals"] == DOCS_APPROVALS
    assert bp["dismiss_stale_approvals"] is True and bp["block_on_rejected_reviews"] is True
    assert bp["enable_status_check"] is True and bp["status_check_contexts"] == CONTEXTS
    assert bp["apply_to_admins"] is True   # D3: no administrator merges past Vale


def test_docs_tags_limited_to_owners_and_maintainers():
    r = forge_api("GET", f"/api/v1/repos/{DOCS_REPO}/tag_protections")
    assert r.status_code == 200
    assert len(r.json()) == 1, r.json()
    t = r.json()[0]
    assert t["name_pattern"] == "*"
    assert set(t["whitelist_teams"]) == {"Owners", "maintainers"} and t["whitelist_usernames"] == []


def test_docs_deploy_repo_public_and_protected():
    r = forge_api("GET", f"/api/v1/repos/{DOCS_DEPLOY_REPO}").json()
    assert (r["private"], r["has_actions"], r["has_packages"]) == (False, True, False)
    assert r["default_merge_style"] == "fast-forward-only"
    assert forge_api("GET", f"/api/v1/repos/{DOCS_DEPLOY_REPO}/branches/main").status_code == 200
    bp = forge_api("GET", f"/api/v1/repos/{DOCS_DEPLOY_REPO}/branch_protections/main").json()
    assert bp["enable_push"] is False and bp["require_signed_commits"] is True
    assert bp["enable_merge_whitelist"] is True and bp["enable_approvals_whitelist"] is True
    assert bp["merge_whitelist_teams"] == ["Owners"] and bp["approvals_whitelist_teams"] == ["Owners"]


def test_docs_has_no_actions_secret():
    """Forgejo hands a job's runner every secret of its repo and org (F1), and the docs build runs code that
    outsiders propose, so neither realliance/docs nor the realliance org may hold one."""
    for path in (f"/api/v1/repos/{DOCS_REPO}/actions/secrets", "/api/v1/orgs/realliance/actions/secrets"):
        r = forge_api("GET", path)
        assert r.status_code == 200, f"{path}: {r.status_code}"
        assert [s["name"] for s in r.json()] == [], path
