"""Task 7 — the box applies main from GitHub, signed commits only."""
import subprocess
import uuid

import pytest
import yaml

from conftest import REPO

OPS = yaml.safe_load((REPO / "operators.yml").read_text())
TRUSTED_FPRS = [o["gpg_fingerprint"] for o in OPS["operators"]] + [OPS["github_web_flow_fingerprint"]]
URL = "https://github.com/realliance/sso.git"
PULL_ENV = "GNUPGHOME=/etc/realliance-sso/gnupg ANSIBLE_COLLECTIONS_PATH=/opt/ansible/collections"


@pytest.fixture
def unsigned_branch():
    name = f"pull-test-unsigned-{uuid.uuid4().hex[:8]}"
    run = lambda *a: subprocess.run(["git", "-C", str(REPO), *a], check=True, capture_output=True)
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "origin/main"], check=True,
                          capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(REPO), "rev-parse", f"{head}^{{tree}}"], check=True,
                          capture_output=True, text=True).stdout.strip()
    commit = subprocess.run(["git", "-C", str(REPO), "commit-tree", tree, "-p", head, "-m", "unsigned test commit"],
                            check=True, capture_output=True, text=True).stdout.strip()
    run("push", "-q", "origin", f"{commit}:refs/heads/{name}")
    yield name
    run("push", "-q", "origin", "--delete", name)


def test_timer_active(host):
    timer = host.service("sso-pull.timer")
    assert timer.is_enabled and timer.is_running


def test_daily_full_run_timer_active(host):
    timer = host.service("sso-pull-daily.timer")
    assert timer.is_enabled and timer.is_running


def test_keyring_has_operators_and_web_flow(host):
    out = host.check_output("GNUPGHOME=/etc/realliance-sso/gnupg gpg --list-keys --with-colons")
    for fpr in TRUSTED_FPRS:
        assert fpr in out


def test_keyring_has_only_trusted_keys(host):
    out = host.check_output("GNUPGHOME=/etc/realliance-sso/gnupg gpg --list-keys --with-colons")
    fprs = {l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")}
    primary = {f for f in fprs if f in TRUSTED_FPRS}
    assert primary == set(TRUSTED_FPRS)
    assert "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23" not in fprs  # expired 2017 web-flow key


def test_pull_accepts_web_flow_signed(host):
    # main's head is a squash-merge made in GitHub, signed by the web-flow key
    host.run_expect([0], "systemctl start sso-pull-full.service")
    assert host.check_output("systemctl show sso-pull-full.service -p Result") == "Result=success"


def test_pull_rejects_unsigned(host, unsigned_branch):
    r = host.run(f"{PULL_ENV} /opt/ansible/bin/ansible-pull -U {URL} -C {unsigned_branch} "
                 f"-d /tmp/pull-test --verify-commit -i host/inventory-pull.yml host/site.yml")
    host.run("rm -rf /tmp/pull-test")
    assert r.rc != 0 and "signature" in (r.stderr + r.stdout).lower()
