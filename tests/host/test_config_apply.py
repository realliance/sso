"""Task 13 — the box applies realm/ and realliance/sso-people itself. Invites Task 4 — sso-people heads are
checked by sso-ledger (operator keys and the ledger key, never web-flow), from the changeover anchor."""
import json
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

from conftest import GROUP_VARS, REPO, SECRETS

PEOPLE_LOCAL = Path.home() / "Repos/realliance-sso-people"
OPS = yaml.safe_load((REPO / "operators.yml").read_text())
OPERATOR_FPRS = [o["gpg_fingerprint"].upper() for o in OPS["operators"]]
LEDGER_FPRS = [f.upper() for f in OPS["ledger_signing_fingerprints"]]
WEB_FLOW_FPR = OPS["github_web_flow_fingerprint"].upper()
HANDED = "/var/lib/sso-config-apply/ledger/handed.json"
# Lines sso-config-apply prints with ids only (shas, codes, counts): safe in an assert message, unlike tofu's.
ID_LINES = ("sso-ledger ", "ledger", "no realliance/sso-people apply", "applied realliance/sso", "refusing")


def gh(path):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def id_lines(r) -> str:
    return "\n".join(line for line in (r.stdout + r.stderr).splitlines() if line.startswith(ID_LINES))


def keyring_fprs(host, home) -> tuple[set, set]:
    """(primary fingerprints, every fingerprint) in a box keyring."""
    lines = host.check_output(f"GNUPGHOME={home} gpg --batch --list-keys --with-colons").splitlines()
    every = {line.split(":")[9] for line in lines if line.startswith("fpr:")}
    primaries = {lines[i + 1].split(":")[9] for i, line in enumerate(lines[:-1])
                 if line.startswith("pub:") and lines[i + 1].startswith("fpr:")}
    return primaries, every


def ledger_env(host) -> dict:
    f = host.file("/etc/realliance-sso/ledger.env")
    assert f.mode == 0o600
    return dict(line.split("=", 1) for line in f.content_string.splitlines() if line and not line.startswith("#"))


@pytest.fixture
def unsigned_people_branch():
    """An unsigned commit on top of sso-people's current main, on a throwaway branch: (branch, its parent)."""
    name = f"apply-test-unsigned-{uuid.uuid4().hex[:8]}"
    run = lambda *a: subprocess.run(["git", "-C", str(PEOPLE_LOCAL), *a], check=True, capture_output=True, text=True)
    run("fetch", "-q", "origin", "main")
    head = run("rev-parse", "origin/main").stdout.strip()
    tree = run("rev-parse", f"{head}^{{tree}}").stdout.strip()
    commit = run("commit-tree", tree, "-p", head, "-m", "unsigned test commit").stdout.strip()
    run("push", "-q", "origin", f"{commit}:refs/heads/{name}")
    yield name, head
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
    # The people plan takes the guests the box last handed: without them it would plan to destroy every guest,
    # and prevent_destroy would fail it.
    people_vars = f" -var-file={HANDED}" if host.file(HANDED).exists else ""
    for d, extra in (("/var/lib/sso-pull/realm", ""), ("/var/lib/sso-people", people_vars)):
        r = host.run(f"{env}; /usr/local/bin/tofu -chdir={d} plan -detailed-exitcode -input=false -no-color{extra}")
        assert r.rc == 0, f"{d}: {r.stdout[-800:]}"


def test_unsigned_people_head_never_applied(host, unsigned_people_branch):
    """The test branch runs in throwaway ledger state, anchored at main's last good: in check mode people.yaml
    applies from the commit below the unsigned head, in apply mode the walk freezes and nothing applies."""
    name, parent = unsigned_people_branch
    r = host.run(f"PEOPLE_REF={name} /usr/local/sbin/sso-config-apply force")
    said = id_lines(r)
    frozen = "frozen: invalid:unsigned@" in said
    assert frozen, said
    if GROUP_VARS["ledger_mode"] == "check":
        applied_below = f"realliance/sso-people {parent} " in said
        assert r.rc == 0 and applied_below, said
    else:
        assert r.rc == 1 and "no realliance/sso-people apply" in said, said
    left = host.check_output("find /var/lib/sso-config-apply -maxdepth 1 -name 'ledger-ref.*' | wc -l")
    assert left == "0"


# --- invites Task 4: the ledger check ------------------------------------------------------------------------

def test_people_keyring_holds_operators_and_ledger_only(host):
    primaries, every = keyring_fprs(host, "/etc/realliance-sso/gnupg-people")
    assert primaries == set(OPERATOR_FPRS + LEDGER_FPRS)
    assert WEB_FLOW_FPR not in every
    trust = json.loads(host.file("/etc/realliance-sso/people-trust.json").content_string)
    assert trust == {"operators": OPERATOR_FPRS, "ledger": LEDGER_FPRS}


def test_pull_keyring_unchanged(host):
    """The pull keyring still trusts web-flow for realliance/sso, and never holds the ledger key."""
    primaries, every = keyring_fprs(host, "/etc/realliance-sso/gnupg")
    assert WEB_FLOW_FPR in primaries and set(OPERATOR_FPRS) <= primaries
    assert not set(LEDGER_FPRS) & every


def test_people_anchor_recorded(host):
    assert ledger_env(host)["PEOPLE_ANCHOR"] == GROUP_VARS["people_anchor_commit"]


def test_ledger_mode_is(host):
    assert ledger_env(host)["LEDGER_MODE"] == GROUP_VARS["ledger_mode"]


def test_people_checkout_full_and_fsck(host):
    assert host.check_output("git -C /var/lib/sso-people rev-parse --is-shallow-repository") == "false"
    assert host.check_output("git -C /var/lib/sso-people config --get fetch.fsckObjects") == "true"


def test_apply_timer_every_minute(host):
    assert GROUP_VARS["apply_interval"] == "1min"
    assert "OnUnitActiveSec=1min" in host.file("/etc/systemd/system/sso-config-apply.timer").content_string


def test_sso_ledger_installed(host):
    assert host.file("/usr/local/sbin/sso-ledger").mode == 0o755
    host.run_expect([0], "/usr/local/sbin/sso-ledger fallback --help")
    assert host.file("/etc/realliance-sso/ledger-lookup.secret").mode == 0o600


def test_people_head_has_both_statuses():
    sha = gh("repos/realliance/sso-people/git/ref/heads/main")["object"]["sha"]
    contexts = {s["context"] for s in gh(f"repos/realliance/sso-people/commits/{sha}/statuses")}
    assert {"sso/apply", "sso/ledger"} <= contexts


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
