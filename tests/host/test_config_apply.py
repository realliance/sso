"""Task 13 — the box applies realm/ and realliance/sso-people itself (signed commits only)."""
import json
import subprocess
import uuid
from pathlib import Path

import pytest

from conftest import GROUP_VARS, SECRETS

PEOPLE_LOCAL = Path.home() / "Repos/realliance-sso-people"


def gh(path):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


@pytest.fixture
def unsigned_people_branch():
    name = f"apply-test-unsigned-{uuid.uuid4().hex[:8]}"
    run = lambda *a: subprocess.run(["git", "-C", str(PEOPLE_LOCAL), *a], check=True, capture_output=True, text=True)
    head = run("rev-parse", "origin/main").stdout.strip()
    tree = run("rev-parse", f"{head}^{{tree}}").stdout.strip()
    commit = run("commit-tree", tree, "-p", head, "-m", "unsigned test commit").stdout.strip()
    run("push", "-q", "origin", f"{commit}:refs/heads/{name}")
    yield name
    run("push", "-q", "origin", "--delete", name)


def test_tofu_pinned(host):
    assert host.check_output("/usr/local/bin/tofu version").startswith(f"OpenTofu v{GROUP_VARS['tofu_version']}")


def test_apply_timers_active(host):
    for t in ("sso-config-apply.timer", "sso-config-apply-full.timer"):
        assert host.service(t).is_enabled and host.service(t).is_running, t


def test_people_deploy_key_registered_read_only(host):
    pub = host.file("/etc/realliance-sso/people_deploy_key.pub").content_string.split()[1]
    keys = gh("repos/realliance/sso-people/keys")
    assert any(pub in k["key"] and k["read_only"] for k in keys)


def test_full_apply_run_succeeds(host):
    host.run_expect([0], "systemctl start sso-config-apply-full.service")
    assert host.check_output("systemctl show sso-config-apply-full.service -p Result") == "Result=success"


def test_box_plans_are_clean(host):
    env = "set -a; . /etc/realliance-sso/tofu.env; set +a"
    for d in ("/var/lib/sso-pull/realm", "/var/lib/sso-people"):
        r = host.run(f"{env}; /usr/local/bin/tofu -chdir={d} plan -detailed-exitcode -input=false -no-color")
        assert r.rc == 0, f"{d}: {r.stdout[-800:]}"


def test_unsigned_people_head_refused(host, unsigned_people_branch):
    r = host.run(f"PEOPLE_REF={unsigned_people_branch} /usr/local/sbin/sso-config-apply force")
    assert r.rc != 0 and "signature" in (r.stdout + r.stderr).lower()


def test_github_holds_no_apply_secret():
    for env in ("plan", "production"):
        names = {s["name"] for s in gh(f"repos/realliance/sso/environments/{env}/secrets")["secrets"]}
        assert not any("APPLY" in n for n in names) and "KEYCLOAK_CLIENT_SECRET_APPLY" not in names


@pytest.mark.skipif("github_status_token" not in SECRETS, reason="commit-status token not supplied yet")
def test_commit_status_reported():
    sha = subprocess.run(["git", "ls-remote", "https://github.com/realliance/sso.git", "main"],
                         check=True, capture_output=True, text=True).stdout.split()[0]
    assert any(s["context"] == "sso/apply" and s["state"] == "success"
               for s in gh(f"repos/realliance/sso/commits/{sha}/statuses"))
