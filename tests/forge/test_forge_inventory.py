"""Forge (project 2b) — the inventory (INVENTORY, in the Owners-only org realliance-ops) owns orgs, teams
and critical repos; members create repos but can never delete or move them away, and never see the
inventory (spec Success 5, 6, 17; plan Task 7 + Review Focus 5; forge-bot plan Task 3)."""
import secrets
import subprocess
from pathlib import Path

import requests

from forge_helpers import FORGE, INVENTORY, forge_api, forge_login, team_members

FORGE_REPO = Path.home() / "Repos/realliance-forge"


def test_inventory_has_no_drift():
    r = subprocess.run(["bash", "-c", "set -a; . ~/Repos/realliance-sso-secrets/forge/secrets.env; "
                        ". ~/Repos/realliance-sso-secrets/b2/secrets.env; set +a; "
                        "export FORGEJO_API_TOKEN=$FORGEJO_ADMIN_TOKEN; "
                        "tofu plan -detailed-exitcode -input=false -no-color >/dev/null"], cwd=FORGE_REPO)
    assert r.returncode == 0


def test_realliance_org_public_to_anonymous():
    r = requests.get(f"{FORGE}/api/v1/orgs/realliance", timeout=20)
    assert r.status_code == 200 and r.json()["visibility"] == "public"


def test_teams_shape():
    teams = {t["name"]: t for t in forge_api("GET", "/api/v1/orgs/realliance/teams").json()}
    assert teams["members"]["permission"] == "write" and teams["members"]["can_create_org_repo"] is True
    assert teams["maintainers"]["permission"] == "admin"
    assert teams["members"]["includes_all_repositories"] and teams["maintainers"]["includes_all_repositories"]
    assert "chris" in team_members("realliance", "Owners")


def test_ops_org_owners_only():
    assert forge_api("GET", "/api/v1/orgs/realliance-ops").json()["visibility"] == "private"
    teams = forge_api("GET", "/api/v1/orgs/realliance-ops/teams").json()
    assert [t["name"] for t in teams] == ["Owners"]
    owners = team_members("realliance-ops", "Owners")
    assert "chris" in owners and owners <= {"chris", "connorjc", "forgejo-admin"}


def test_forge_repo_private_and_protected():
    r = forge_api("GET", f"/api/v1/repos/{INVENTORY}").json()
    assert r["full_name"] == INVENTORY and r["private"] is True
    bp = forge_api("GET", f"/api/v1/repos/{INVENTORY}/branch_protections/main").json()
    assert bp["enable_push"] is False and bp["require_signed_commits"] is True
    assert bp["required_approvals"] == 0  # 1 once Connor is active, like realliance/sso
    # only Owners may merge or approve: members write to every realliance repo (final review, Important 2)
    assert bp["enable_merge_whitelist"] is True and bp["merge_whitelist_teams"] == ["Owners"]
    assert bp["enable_approvals_whitelist"] is True and bp["approvals_whitelist_teams"] == ["Owners"]


def _member(forge_user):
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    forge_login(u)
    return u


def test_member_cannot_see_inventory(forge_user):  # Success 17
    u = _member(forge_user)
    assert forge_api("GET", f"/api/v1/repos/{INVENTORY}", sudo=u.name).status_code == 404


def test_inventory_mirror_current():
    sha = forge_api("GET", f"/api/v1/repos/{INVENTORY}/branches/main").json()["commit"]["id"]
    gh = subprocess.run(["gh", "api", "repos/realliance/forge/commits/main", "--jq", ".sha"],
                        capture_output=True, text=True).stdout.strip()
    assert gh == sha


def test_member_creates_repo_cannot_delete(forge_user):  # Success 6
    u = _member(forge_user)
    name = f"t-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/orgs/realliance/repos", sudo=u.name, json={"name": name}).status_code == 201
    try:
        assert forge_api("DELETE", f"/api/v1/repos/realliance/{name}", sudo=u.name).status_code in (403, 404)
        assert forge_api("GET", f"/api/v1/repos/realliance/{name}").status_code == 200
    finally:
        forge_api("DELETE", f"/api/v1/repos/realliance/{name}")


def test_member_cannot_transfer_org_repo(forge_user):  # Review Focus 5
    u = _member(forge_user)
    name = f"t-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/orgs/realliance/repos", sudo=u.name, json={"name": name}).status_code == 201
    try:
        r = forge_api("POST", f"/api/v1/repos/realliance/{name}/transfer", sudo=u.name, json={"new_owner": u.name})
        assert r.status_code in (403, 404)
        assert forge_api("GET", f"/api/v1/repos/realliance/{name}").json()["owner"]["login"] == "realliance"
    finally:
        forge_api("DELETE", f"/api/v1/repos/realliance/{name}")


def test_private_org_invisible(forge_user):  # Success 5
    org = f"test-{secrets.token_hex(4)}"
    assert forge_api("POST", "/api/v1/orgs", json={"username": org, "visibility": "private"}).status_code == 201
    try:
        assert requests.get(f"{FORGE}/api/v1/orgs/{org}", timeout=20).status_code == 404
        assert org not in requests.get(f"{FORGE}/explore/organizations", timeout=20).text
        u = forge_user()
        forge_login(u)
        assert forge_api("GET", f"/api/v1/orgs/{org}", sudo=u.name).status_code == 404
    finally:
        forge_api("DELETE", f"/api/v1/orgs/{org}")


def test_public_repo_visible_to_anonymous():
    name = f"t-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/orgs/realliance/repos", json={"name": name, "private": False}).status_code == 201
    try:
        assert requests.get(f"{FORGE}/api/v1/repos/realliance/{name}", timeout=20).status_code == 200
    finally:
        forge_api("DELETE", f"/api/v1/repos/realliance/{name}")


def _maintainer(forge_user):
    u = forge_user(groups=("/apps/forgejo", "/realliance", "/realliance-maintainers"))
    forge_login(u)
    assert u.name in team_members("realliance", "maintainers")
    return u


def test_maintainer_cannot_delete_or_transfer(forge_user):  # final review, Important 1
    u = _maintainer(forge_user)
    name = f"t-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/orgs/realliance/repos", json={"name": name}).status_code == 201
    try:
        r = forge_api("POST", f"/api/v1/repos/realliance/{name}/transfer", sudo=u.name, json={"new_owner": u.name})
        assert r.status_code in (403, 404), f"maintainer transfer: {r.status_code}"
        r = forge_api("DELETE", f"/api/v1/repos/realliance/{name}", sudo=u.name)
        assert r.status_code in (403, 404), f"maintainer delete: {r.status_code}"
        assert forge_api("GET", f"/api/v1/repos/realliance/{name}").json()["owner"]["login"] == "realliance"
    finally:
        forge_api("DELETE", f"/api/v1/repos/realliance/{name}")
