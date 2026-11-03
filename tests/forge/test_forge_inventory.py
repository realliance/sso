"""Forge (project 2b) — the realliance/forge inventory owns orgs, teams and critical repos; members
create repos but can never delete or move them away (spec Success 5, 6; plan Task 7 + Review Focus 5)."""
import secrets
import subprocess
from pathlib import Path

import requests

from forge_helpers import FORGE, forge_api, forge_login

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
    owners = forge_api("GET", f"/api/v1/teams/{teams['Owners']['id']}/members").json()
    assert "chris" in {m["login"] for m in owners}


def test_forge_repo_private_and_protected():
    assert forge_api("GET", "/api/v1/repos/realliance/forge").json()["private"] is True
    bp = forge_api("GET", "/api/v1/repos/realliance/forge/branch_protections/main").json()
    assert bp["enable_push"] is False and bp["require_signed_commits"] is True
    assert bp["required_approvals"] == 0  # 1 once Connor is active, like realliance/sso


def _member(forge_user):
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    forge_login(u)
    return u


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
