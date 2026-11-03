"""Forge CI: forge-ci's package token, and galaxy's runner — host mode, label `galaxy`, registered for
realliance/forge-bot only, unprivileged, with no bot or admin secret in reach and a fresh workspace per job."""
import re
import secrets
import time

import pytest
import yaml

from conftest import SECRETS, _load_env
from forge_helpers import (CYCLE_WAIT, FORGE_BOT_REPO, FORGE_SECRETS, LUMA, PACKAGE_TOKEN_REPO_SCOPED,
                           anonymous_manifest, b2_names, delete_branch, forge_api, galaxy_only, kube, manifests,
                           oci_push, push_probe_workflow, runs_for, wait_for)

RUNNER_DIR = LUMA / "cluster/forgejo-runner"
SETTLED = {"success", "failure", "cancelled", "skipped"}

# A job the runner must run: as uid 1000, with no Docker socket and no service-account token, with the
# toolchain on PATH, and in a workspace under /work/act that no earlier job left anything in. The find is
# an assignment so `set -e` catches a find error, and the last line is the positive control: the same
# find does see this job's own leftover.
PROBE_SCRIPT = """\
set -eu
test "$(id -u)" = 1000
test ! -e /var/run/docker.sock
test ! -e /var/run/secrets/kubernetes.io
go version
ko version
node --version
case "$GITHUB_WORKSPACE" in /work/act/*) ;; *) echo "workspace $GITHUB_WORKSPACE is not under /work/act" >&2; exit 1;; esac
left=$(find /work/act -name 'leftover-*')
test -z "$left"
touch "$GITHUB_WORKSPACE/leftover-$GITHUB_RUN_NUMBER"
find /work/act -name "leftover-$GITHUB_RUN_NUMBER" | grep -q .
"""


def test_package_token_scope():
    tok = _load_env(FORGE_SECRETS)["FORGE_CI_PACKAGE_TOKEN"]
    tag = f"probe-{secrets.token_hex(3)}"
    try:
        pushed = oci_push("realliance/forge-bot", tag, "forge-ci", tok)
        assert pushed == 201
        assert anonymous_manifest("realliance/forge-bot", tag).status_code == 200   # public with the org
        foreign = oci_push("forge-bot/b0-probe", tag, "forge-ci", tok)
        assert foreign in (401, 403)   # another owner
        other = oci_push("realliance/b0-other", tag, "forge-ci", tok)
        assert other in (401, 403) if PACKAGE_TOKEN_REPO_SCOPED else other == 201
    finally:
        for name in ("forge-bot", "b0-other"):
            forge_api("DELETE", f"/api/v1/packages/realliance/container/{name}/{tag}")
        forge_api("DELETE", f"/api/v1/packages/forge-bot/container/b0-probe/{tag}")   # best effort; 404 is fine


def test_runner_manifests_unprivileged():                         # Success 17
    docs = manifests(RUNNER_DIR)
    ns = next(x for x in docs if x["kind"] == "Namespace")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "baseline"
    specs = [x["spec"]["template"]["spec"] for x in docs if x["kind"] == "Deployment"]
    assert specs
    for spec in specs:
        assert spec["automountServiceAccountToken"] is False and spec["enableServiceLinks"] is False
        assert not any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC"))
        assert not any("hostPath" in v for v in spec.get("volumes", []))
        assert spec["securityContext"]["runAsNonRoot"] is True
        assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        for c in spec["containers"] + spec.get("initContainers", []):
            sc = c["securityContext"]
            assert sc.get("privileged") is not True and sc["allowPrivilegeEscalation"] is False
            assert sc["capabilities"] == {"drop": ["ALL"]} and "docker.sock" not in yaml.safe_dump(c)


def test_runner_start_clears_job_state():
    # Jobs inherit the runner's HOME and TMPDIR, and both live on the PVC. Recreating the pod must clear them,
    # plus any workspace a killed job left behind (spec: "the runner pod can be recreated to clear everything
    # else"). Only the caches and the registration survive.
    dep = next(x for x in manifests(RUNNER_DIR) if x["kind"] == "Deployment")
    c = next(x for x in dep["spec"]["template"]["spec"]["containers"] if x["name"] == "runner")
    assert c["command"][:2] == ["sh", "-c"]
    script = c["command"][2]
    assert "exec forgejo-runner daemon" in script
    before_exec = script.split("exec ", 1)[0]
    cleared = {p.rstrip("/") for m in re.findall(r"\brm -rf ([^&;|]+)", before_exec) for p in m.split()}
    assert {"/work/home", "/work/tmp", "/work/act"} <= cleared
    assert before_exec.index("rm -rf") < before_exec.index("mkdir -p")
    every_rm = {p.rstrip("/") for m in re.findall(r"\brm(?:\s+-\w+)*\s+([^&;|]+)", script) for p in m.split()}
    assert not any(p in ("/work", "/work/cache", "/work/.runner") or p.startswith("/work/cache/") or "*" in p
                   for p in every_rm), every_rm


def test_runner_registered_with_galaxy_label_only():
    rs = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/actions/runners").json()
    # Forgejo 15 lists labels as plain name strings; a `name:scheme` entry would still compare by name.
    assert rs and all({l.split(":")[0] for l in r["labels"]} == {"galaxy"} for r in rs)


def _settled(repo: str, sha: str) -> list[str] | None:
    """The statuses of the commit's runs once every one of them has finished, else None."""
    statuses = [r["status"] for r in runs_for(repo, sha)]
    return statuses if statuses and set(statuses) <= SETTLED else None


def test_probe_job_hardened_and_workspace_wiped():
    # Two commits on one probe branch, one after the other. The second run passing proves the first
    # run's workspace was wiped: its find would see leftover-<first run number>.
    branch = None
    try:
        for attempt in (1, 2):
            branch, sha = push_probe_workflow(FORGE_BOT_REPO, "galaxy", PROBE_SCRIPT, branch)
            assert wait_for(lambda: _settled(FORGE_BOT_REPO, sha) is not None, timeout=CYCLE_WAIT), \
                f"probe run {attempt} did not finish within {CYCLE_WAIT} s"
            statuses = _settled(FORGE_BOT_REPO, sha)
            assert statuses == ["success"], f"probe run {attempt}: {statuses}"
    finally:
        if branch:
            delete_branch(FORGE_BOT_REPO, branch)


@pytest.mark.slow
def test_allowlist_jobs_wait():                                   # Success 15
    # (a) a scratch repo the runner is not registered for, asking for `galaxy`; (b) forge-bot asking for a
    # GitHub-style label the runner does not carry. Neither may ever be picked up.
    scratch = f"realliance/ci-probe-{secrets.token_hex(4)}"
    branch = None
    try:
        r = forge_api("POST", "/api/v1/orgs/realliance/repos",
                      json={"name": scratch.split("/")[1], "private": True, "auto_init": True,
                            "default_branch": "main"})
        assert r.status_code == 201, r.text
        r = forge_api("PATCH", f"/api/v1/repos/{scratch}", json={"has_actions": True})
        assert r.status_code == 200, r.text
        _, sha_a = push_probe_workflow(scratch, "galaxy", "true")
        branch, sha_b = push_probe_workflow(FORGE_BOT_REPO, "ubuntu-latest", "true")
        started = time.monotonic()
        targets = [(scratch, sha_a), (FORGE_BOT_REPO, sha_b)]
        for repo, sha in targets:   # each probe made a run, or "all waiting" below would hold vacuously
            assert wait_for(lambda: bool(runs_for(repo, sha)), timeout=120), f"no run for the probe in {repo}"
        time.sleep(max(0.0, 600 - (time.monotonic() - started)))
        for repo, sha in targets:
            statuses = [x["status"] for x in runs_for(repo, sha)]
            assert statuses, f"no run for the probe in {repo}"
            assert set(statuses) == {"waiting"}, f"{repo}: {statuses}"
        # ... and the runner was online all along, or "never picked up" would prove nothing.
        runners = {r["name"]: r["status"] for r in
                   forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/actions/runners").json()}
        assert runners.get("galaxy-forge-bot") in ("idle", "active"), f"runner not online: {runners}"
    finally:
        forge_api("DELETE", f"/api/v1/repos/{scratch}")
        if branch:
            delete_branch(FORGE_BOT_REPO, branch)   # Forgejo's abandoned-job cron cancels (b) after 24 h


def test_actions_logs_in_b2():
    assert b2_names("realliance-forge-objects", "actions_log/")


@galaxy_only
def test_runner_pod_holds_no_bot_or_admin_secrets():              # Success 17
    env = _load_env(FORGE_SECRETS)
    values = [env.get("FORGEJO_ADMIN_TOKEN"), env.get("FORGE_BOT_FORGEJO_TOKEN"),
              SECRETS.get("forge_bot_client_secret")]
    present = sum(bool(v) for v in values)   # an empty pattern would match everything
    assert present == 3, "a canonical bot/admin secret is missing from sso-secrets"
    base = ("-n", "forgejo-runner", "exec", "-i", "deploy/forgejo-runner", "--")
    scan = (*base, "sh", "-c", "grep -rqsF -f /dev/stdin /etc /work /home /tmp /proc/1/environ")
    # Positive controls: present, non-secret strings (one in the sealed config.yml, one in PID 1's
    # environment) must be found by the very same scan, or "not found" below would prove nothing.
    for control in ("workdir_parent", "HOME=/work/home"):
        hit = kube(*scan, stdin=control)
        assert hit.returncode == 0, f"control {control!r} not found (exit {hit.returncode})"
    for v in values:   # the value travels on stdin only; never in the message
        r = kube(*scan, stdin=v)
        # grep: 1 = no match, 2 = no match but an unreadable file (e.g. /etc/shadow; -s keeps it quiet).
        # 0 = match; 126/127 = no grep. A kubectl exec failure also exits 1, but with its own error on
        # stderr; a clean remote exit only adds kubectl's "command terminated with exit code N".
        assert r.returncode in (1, 2), f"a bot/admin secret is readable in the runner pod, or the scan failed (exit {r.returncode})"
        noise = r.stderr.strip()
        assert noise in ("", f"command terminated with exit code {r.returncode}"), f"the scan did not run cleanly: {noise[:200]}"
