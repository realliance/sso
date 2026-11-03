"""Task 12 — realliance/sso-people: people.yaml drives users, activation and exact memberships.

Runs the private repo's real OpenTofu code in a sandbox copy with a local state file, against the
live realm, with throwaway users (invites go to Resend's test inbox).
"""
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest
import requests
import yaml

from conftest import REALM, SECRETS_DIR, SSO, _load_env, admin_token, get, group_id

PEOPLE_REPO = Path(os.environ.get("SSO_PEOPLE_DIR", Path.home() / "Repos/realliance-sso-people"))


def _tofu(d, *args, check=True):
    env = dict(os.environ, **_load_env(SECRETS_DIR / "realm/secrets.env"))
    r = subprocess.run(["tofu", f"-chdir={d}", *args, "-input=false", "-no-color"],
                       env=env, capture_output=True, text=True)
    if check:
        assert r.returncode == 0, r.stdout[-1500:] + r.stderr[-1500:]
    return r


def _write(d, people, hidden=()):
    (d / "people.yaml").write_text(yaml.safe_dump({"hidden_groups": list(hidden), "people": people}))


def _person(username, active=True, groups=("/realliance",)):
    return {"username": username, "active": active, "groups": list(groups),
            "bootstrap": {"email": f"delivered+{username}@resend.dev", "first_name": "Test", "last_name": "Person"}}


def _user(username):
    users = get(f"/admin/realms/{REALM}/users", admin_token(), params={"username": username, "exact": "true"}).json()
    return users[0] if users else None


def _groups_of(uid):
    return {g["name"] for g in get(f"/admin/realms/{REALM}/users/{uid}/groups", admin_token()).json()}


@pytest.fixture(params=[False], ids=["unprotected"])
def sandbox(tmp_path, request):
    d = tmp_path / "people"
    shutil.copytree(PEOPLE_REPO, d, ignore=shutil.ignore_patterns(".git", ".terraform", "*.tfstate*"))
    (d / "backend_override.tf").write_text('terraform {\n  backend "local" {}\n}\n')
    if not request.param:  # unprotected copy so the test can clean up; protection is tested separately
        main = d / "main.tf"
        main.write_text(re.sub(r"\n\s*prevent_destroy = true", "", main.read_text()))
    _tofu(d, "init")
    made = {"users": set(), "groups": set()}
    yield d, made
    token = admin_token()
    for name in made["users"]:
        u = _user(name)
        if u:
            requests.delete(f"{SSO}/admin/realms/{REALM}/users/{u['id']}", timeout=20,
                            headers={"Authorization": f"Bearer {token}"})
    for name in made["groups"]:
        try:
            requests.delete(f"{SSO}/admin/realms/{REALM}/groups/{group_id('/' + name)}", timeout=20,
                            headers={"Authorization": f"Bearer {token}"})
        except requests.HTTPError:
            pass


def test_person_created_enabled_with_exact_groups(sandbox):
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name, groups=["/realliance"])])
    _tofu(d, "apply", "-auto-approve")
    u = _user(name)
    assert u["enabled"] is True and _groups_of(u["id"]) == {"realliance"}
    # a membership added outside Git is removed on the next apply
    requests.put(f"{SSO}/admin/realms/{REALM}/users/{u['id']}/groups/{group_id('/realmic')}", timeout=20,
                 headers={"Authorization": f"Bearer {admin_token()}"}).raise_for_status()
    _tofu(d, "apply", "-auto-approve")
    assert _groups_of(u["id"]) == {"realliance"}


def test_inactive_person_is_disabled(sandbox):
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name)])
    _tofu(d, "apply", "-auto-approve")
    _write(d, [_person(name, active=False)])
    _tofu(d, "apply", "-auto-approve")
    assert _user(name)["enabled"] is False


def test_hidden_group_created_and_joined(sandbox):
    d, made = sandbox
    name, hidden = f"t-{secrets.token_hex(4)}", f"hid-{secrets.token_hex(4)}"
    made["users"].add(name)
    made["groups"].add(hidden)
    _write(d, [_person(name, groups=["/realliance", f"/{hidden}"])], hidden=[hidden])
    _tofu(d, "apply", "-auto-approve")
    assert _groups_of(_user(name)["id"]) == {"realliance", hidden}


@pytest.mark.parametrize("sandbox", [True], ids=["protected"], indirect=True)
def test_removing_a_person_is_refused(sandbox):
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name)])
    _tofu(d, "apply", "-auto-approve")
    _write(d, [])
    r = _tofu(d, "plan", check=False)
    assert r.returncode != 0 and "prevent_destroy" in (r.stdout + r.stderr)


def test_real_people_yaml_is_valid():
    doc = yaml.safe_load((PEOPLE_REPO / "people.yaml").read_text())
    people, hidden = doc["people"], set(doc.get("hidden_groups") or [])
    names = [p["username"] for p in people]
    assert len(names) == len(set(names))
    for p in people:
        assert re.fullmatch(r"[a-z][a-z0-9-]{1,30}", p["username"]), p["username"]
        assert not {"email", "first_name", "last_name"} & p.keys(), f"{p['username']}: profile fields go under bootstrap"
        b = p["bootstrap"]
        assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", b["email"]), p["username"]
        assert isinstance(p["active"], bool) and b["first_name"]
        assert b.get("last_name", "x"), f"{p['username']}: omit last_name rather than leave it empty"
        assert all(g.startswith("/") for g in p["groups"]), p["username"]
        assert p.get("mfa", "webauthn") in ("webauthn", "totp"), p["username"]
    assert not hidden & {"realmic", "realliance", "apps"}


def test_mfa_preference_attribute(sandbox):
    d, made = sandbox
    a, b = f"t-{secrets.token_hex(4)}", f"t-{secrets.token_hex(4)}"
    made["users"].update({a, b})
    totp = _person(b)
    totp["mfa"] = "totp"
    _write(d, [_person(a), totp])
    _tofu(d, "apply", "-auto-approve")
    assert _user(a)["attributes"]["mfa"] == ["webauthn"]
    assert _user(b)["attributes"]["mfa"] == ["totp"]


def test_people_own_their_profile_after_creation(sandbox):
    """Email and name are bootstrap values: a person's own edits in Keycloak survive every apply."""
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name)])
    _tofu(d, "apply", "-auto-approve")
    u = _user(name)
    u.update(email=f"delivered+{name}-new@resend.dev", firstName="Renamed", lastName="Self")
    requests.put(f"{SSO}/admin/realms/{REALM}/users/{u['id']}", json=u, timeout=20,
                 headers={"Authorization": f"Bearer {admin_token()}"}).raise_for_status()
    assert _tofu(d, "plan", "-detailed-exitcode", check=False).returncode == 0
    _tofu(d, "apply", "-auto-approve")
    after = _user(name)
    assert (after["email"], after["firstName"], after["lastName"]) == (f"delivered+{name}-new@resend.dev", "Renamed", "Self")


def test_bootstrap_edits_after_creation_change_nothing(sandbox):
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name)])
    _tofu(d, "apply", "-auto-approve")
    p = _person(name)
    p["bootstrap"]["first_name"] = "Changed"
    _write(d, [p])
    assert _tofu(d, "plan", "-detailed-exitcode", check=False).returncode == 0


def test_person_without_last_name(sandbox):
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    p = _person(name)
    del p["bootstrap"]["last_name"]
    _write(d, [p])
    _tofu(d, "apply", "-auto-approve")
    u = _user(name)
    assert u["firstName"] == "Test" and not u.get("lastName")


def test_self_set_profile_attributes_survive_apply(sandbox):
    """Attributes a person sets themselves (pronouns; later picture) are never wiped by an apply."""
    d, made = sandbox
    name = f"t-{secrets.token_hex(4)}"
    made["users"].add(name)
    _write(d, [_person(name)])
    _tofu(d, "apply", "-auto-approve")
    u = _user(name)
    u.setdefault("attributes", {})["pronouns"] = ["she/her"]
    requests.put(f"{SSO}/admin/realms/{REALM}/users/{u['id']}", json=u, timeout=20,
                 headers={"Authorization": f"Bearer {admin_token()}"}).raise_for_status()
    assert _tofu(d, "plan", "-detailed-exitcode", check=False).returncode == 0
    _tofu(d, "apply", "-auto-approve")
    assert _user(name)["attributes"].get("pronouns") == ["she/her"]
