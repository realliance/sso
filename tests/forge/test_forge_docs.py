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


def test_docs_fork_pr_run_waits_for_approval(forge_user):
    """C9: Forgejo 15's API has no setting for approving fork runs, so this proves the built-in rule: a PR from a
    fork of a non-member starts a run that waits for approval, with no task started. DOCS_FORK_FROM names the
    branch to fork from, main by default; set it to test before the workflow reaches main. Never leave it set
    in a shell or in CI: a fork of a branch with a different workflow proves nothing about main."""
    import base64
    import os
    import secrets

    from forge_helpers import forge_login, wait_for
    u = forge_user(groups=("/apps/forgejo",))
    forge_login(u)   # the first sign-in creates the forge account
    me = u.name
    base = os.environ.get("DOCS_FORK_FROM", "main")   # its own line: the secrets guard taints names bound with an environ read
    branch = f"fork-{secrets.token_hex(3)}"
    pr = None
    try:
        r = forge_api("POST", f"/api/v1/repos/{DOCS_REPO}/forks", sudo=me, json={})
        assert r.status_code == 202, r.text
        fork = f"{me}/docs"
        assert wait_for(lambda: forge_api("GET", f"/api/v1/repos/{fork}").status_code == 200, timeout=60, every=2)
        r = forge_api("POST", f"/api/v1/repos/{fork}/branches", sudo=me,
                      json={"new_branch_name": branch, "old_ref_name": base})
        assert r.status_code == 201, r.text
        # a page, else the README (main holds only the README until the first merge)
        for name in ("content/docs/index.mdx", "README.md"):
            path = f"/api/v1/repos/{fork}/contents/{name}"
            cur = forge_api("GET", path, sudo=me, params={"ref": branch})
            if cur.status_code == 200:
                cur = cur.json()
                break
        text = base64.b64decode(cur["content"]).decode() + "\nA fork's one-line change.\n"
        r = forge_api("PUT", path, sudo=me, json={"branch": branch, "sha": cur["sha"], "message": "a fork's change",
                                                  "content": base64.b64encode(text.encode()).decode()})
        assert r.status_code == 200, r.text
        sha = r.json()["commit"]["sha"]
        r = forge_api("POST", f"/api/v1/repos/{DOCS_REPO}/pulls", sudo=me,
                      json={"title": "fork probe", "base": "main", "head": f"{me}:{branch}"})
        assert r.status_code == 201, r.text
        pr = r.json()["number"]

        def mine():
            runs = forge_api("GET", f"/api/v1/repos/{DOCS_REPO}/actions/runs",
                             params={"event": "pull_request", "head_sha": sha}).json()["workflow_runs"]
            return runs
        assert wait_for(lambda: bool(mine()), timeout=120, every=5), "no run for the fork's head within 2 minutes"
        runs = mine()
        assert all(x.get("need_approval") is True for x in runs), runs
        assert all(x.get("is_fork_pull_request") is True and x.get("status") in ("blocked", "waiting") for x in runs), \
            [(x.get("status"), x.get("is_fork_pull_request")) for x in runs]   # no task has started
    finally:
        if pr:
            forge_api("PATCH", f"/api/v1/repos/{DOCS_REPO}/pulls/{pr}", json={"state": "closed"})
        forge_api("DELETE", f"/api/v1/repos/{me}/docs")
