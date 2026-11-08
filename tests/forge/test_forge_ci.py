"""Forge CI: the package tokens (ops-ci's for realliance-ops; realliance-ci's for realliance.net), and galaxy's
runner — host mode, label `galaxy`, registered for the forge's bots only, unprivileged, with no bot or admin
secret in reach and a fresh workspace per job."""
import re
import secrets
import time

import pytest
import requests
import yaml

from conftest import SECRETS, _load_env
from forge_helpers import (CI_DISPATCH_REPO, CYCLE_WAIT, FORGE, FORGE_BOT_REPO, FORGE_SECRETS, LUMA,
                           anonymous_manifest, assert_pod_hardened, b2_names, delete_branch, forge_api, galaxy_only,
                           kube, manifests, oci_push, push_probe_workflow, runs_for, wait_for)

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


def test_realliance_has_no_registry_token():
    """The `realliance` org holds no package token: its REGISTRY_TOKEN (forge-ci's) went with the bots' move to
    realliance-ops (bots-to-realliance-ops D8, Task 8). The one realliance package token is realliance.net's
    repo secret (test_site_registry_token_scope). Names only, never values."""
    names = {s["name"] for s in forge_api("GET", "/api/v1/orgs/realliance/actions/secrets").json() or []}
    assert "REGISTRY_TOKEN" not in names


@galaxy_only
def test_forge_ci_holds_no_token():
    """forge-ci's write:package token was deleted from Forgejo's database (D8): the token routes take only
    password Basic auth, which this forge turns off, so the API can't revoke it. A read-only count; a new
    forge-ci token, or a restore from a dump older than 2026-11-04, shows up here."""
    r = kube("-n", "forgejo", "exec", "acid-forgejo-0", "-c", "postgres", "--", "psql", "-U", "postgres", "-d",
             "forgejo", "-tA", "-c",
             "select count(*) from access_token t join \"user\" u on u.id = t.uid where u.lower_name = 'forge-ci'")
    assert r.returncode == 0, f"reading access_token failed: {r.stderr[-200:]}"
    assert r.stdout.strip() == "0"


def test_ops_ci_account():
    """ops-ci pushes the bots' images in realliance-ops (team ci: packages only, no repos). A local account,
    not a site administrator."""
    a = forge_api("GET", "/api/v1/users/ops-ci").json()
    assert (a.get("login"), a.get("source_id"), a.get("is_admin")) == ("ops-ci", 0, False)


def test_ops_registry_token_scope():
    """ops-ci's write:package token (the realliance-ops org secret REGISTRY_TOKEN) pushes in realliance-ops and
    never in realliance. Throwaway packages only."""
    tok = _load_env(FORGE_SECRETS)["OPS_CI_PACKAGE_TOKEN"]
    tag, probe = f"probe-{secrets.token_hex(3)}", f"ci-probe-{secrets.token_hex(4)}"
    try:
        pushed = oci_push(f"realliance-ops/{probe}", tag, "ops-ci", tok)
        assert pushed == 201
        assert anonymous_manifest(f"realliance-ops/{probe}", tag).status_code == 200   # public with the org (D5)
        other_org = oci_push(f"realliance/{probe}", tag, "ops-ci", tok)
        assert other_org in (401, 403)
    finally:
        for owner in ("realliance-ops", "realliance"):   # best effort; 404 is fine
            forge_api("DELETE", f"/api/v1/packages/{owner}/container/{probe}/{tag}")


def test_realliance_ci_account():
    """realliance-ci pushes realliance.net's image (team realliance/ci: packages only, no repos). A local
    account, not a site administrator, able to authenticate (prohibit_login would void its package access),
    and in no team but realliance/ci. It reaches no repository."""
    a = forge_api("GET", "/api/v1/users/realliance-ci").json()
    assert (a.get("login"), a.get("source_id"), a.get("is_admin")) == ("realliance-ci", 0, False)
    admin_view = [u for u in forge_api("GET", "/api/v1/admin/users", params={"limit": 50, "q": "realliance-ci"}).json()
                  if u["login"] == "realliance-ci"]
    assert [u["prohibit_login"] for u in admin_view] == [False]
    teams = forge_api("GET", "/api/v1/user/teams", sudo="realliance-ci").json()
    assert [(t["organization"]["username"], t["name"]) for t in teams] == [("realliance", "ci")]
    assert forge_api("GET", "/api/v1/user/repos", sudo="realliance-ci").json() == []


@galaxy_only
def test_realliance_ci_tokens():
    """realliance-ci has exactly two tokens, realliance-net-registry (the site) and realliance-forgejo-registry (the
    fork image), each scoped write:package and nothing else: a
    re-mint with a wider scope pushes just as well, so test_site_registry_token_scope alone would not see it.
    A read-only query of names and scopes, never the hashes."""
    r = kube("-n", "forgejo", "exec", "acid-forgejo-0", "-c", "postgres", "--", "psql", "-U", "postgres", "-d",
             "forgejo", "-tA", "-c",
             "select t.name || ' ' || t.scope from access_token t join \"user\" u on u.id = t.uid"
             " where u.lower_name = 'realliance-ci'")
    assert r.returncode == 0, f"reading access_token failed: {r.stderr[-200:]}"
    assert sorted(r.stdout.split("\n")[:-1]) == ["realliance-forgejo-registry write:package",
                                                 "realliance-net-registry write:package"]


def test_site_registry_token_scope():
    """realliance-ci's write:package token (REALLIANCE_NET_REGISTRY_TOKEN; the realliance/realliance.net repo
    secret SITE_REGISTRY_TOKEN, its only secret) pushes in realliance and never in realliance-ops. Forgejo 15
    has no repo-scoped tokens, so it reaches every realliance package. Throwaway packages only, never
    realliance/realliance.net itself."""
    names = {s["name"] for s in forge_api("GET", "/api/v1/repos/realliance/realliance.net/actions/secrets").json()}
    assert names == {"SITE_REGISTRY_TOKEN"}
    tok = _load_env(FORGE_SECRETS)["REALLIANCE_NET_REGISTRY_TOKEN"]
    tag, probe = f"probe-{secrets.token_hex(3)}", f"ci-probe-{secrets.token_hex(4)}"
    try:
        own = oci_push(f"realliance/{probe}", tag, "realliance-ci", tok)
        other = oci_push(f"realliance-ops/{probe}", tag, "realliance-ci", tok)
        assert own == 201
        assert other in (401, 403)
    finally:
        for owner in ("realliance", "realliance-ops"):   # best effort; 404 is fine
            forge_api("DELETE", f"/api/v1/packages/{owner}/container/{probe}/{tag}")


def test_runner_manifests_unprivileged():                         # Success 17
    docs = manifests(RUNNER_DIR)
    ns = next(x for x in docs if x["kind"] == "Namespace")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "baseline"
    specs = [x["spec"]["template"]["spec"] for x in docs if x["kind"] == "Deployment"]
    assert specs
    for spec in specs:
        assert_pod_hardened(spec)


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


# galaxy netpol B2 (luma-homeops docs/superpowers/specs/2026-11-03-networkpolicy-enforcement-design.md §9.3):
# the job's network is the runner pod's (host mode), which the forgejo-runner NetworkPolicies confine to
# DNS, the forge through the WAN /25 on 443, and the public internet. The rows are the canary matrix's
# `all` rows, less $HOST_IP and $PEER_IP, which need the node a job cannot see. The row for the runner
# node's own BMC stays in: that node cannot reach its own BMC at all, so the row passes without
# proving anything there; the other two nodes' rows still prove it.
EGRESS_SKIP = {"$HOST_IP", "$PEER_IP"}
EGRESS_WANT = {"dns": "open", "open": "open", "dropped": "timeout"}


def _egress_rows() -> list[tuple[str, str, str]]:
    """(expect, host, port) for each `all` row of the canary matrix the job checks."""
    rows = []
    for raw in (LUMA / "cluster/netpol-canary/matrix.txt").read_text().splitlines():
        r = raw.split()
        if r and not r[0].startswith("#") and r[1] == "all" and r[2] not in EGRESS_SKIP:
            rows.append((r[0], r[2], r[3]))
    return rows


def _egress_script() -> str:
    """The job: each row with the canary's connect tool, counting failures, then the CI paths a build
    needs (the forge over the WAN reflection, GitHub, the Go proxy). The root filesystem is read-only,
    so the tool goes to $TMPDIR."""
    js = (LUMA / "scripts/netpol-connect.js").read_text()
    assert "\nJS\n" not in js
    lines = [
        "set -eu",
        "cat > \"$TMPDIR/netpol-connect.js\" <<'JS'",
        js.rstrip("\n"),
        "JS",
        "WAN_IP=$(node -e 'require(\"dns\").lookup(\"git.realliance.net\",{family:4},(e,a)=>{if(e)process.exit(1);console.log(a)})')",
        "fail=0",
        "check() { want=$1; shift; got=$(node \"$TMPDIR/netpol-connect.js\" \"$@\"); "
        "if [ \"$got\" = \"$want\" ]; then echo \"ok $* $got\"; else echo \"FAIL $* got $got\"; fail=$((fail + 1)); fi; }",
    ]
    for expect, host, port in _egress_rows():
        target = '"$WAN_IP"' if host == "$WAN_IP" else host
        if expect == "dns":
            lines.append(f"check open dns {target}")
        else:
            lines.append(f"check {EGRESS_WANT[expect]} tcp {target} {port}")
    lines += [
        "git ls-remote https://git.realliance.net/realliance-ops/forge-bot HEAD",
        "git ls-remote https://github.com/actions/checkout HEAD",
        "go mod download golang.org/x/text@v0.20.0",
        "exit $fail",
    ]
    return "\n".join(lines) + "\n"


def test_runner_job_egress_script():
    """Offline: one check per matrix row the job can expand, each with the outcome the policy wants."""
    script = _egress_script()
    rows = _egress_rows()
    assert rows and not any(h in EGRESS_SKIP for _, h, _ in rows)
    assert script.count("\ncheck ") == len(rows)
    assert script.count("\ncheck timeout tcp ") == sum(e == "dropped" for e, _, _ in rows)
    assert 'check timeout tcp "$WAN_IP" 8585' in script and "check open tcp git.realliance.net 443" in script
    assert script.rstrip().endswith("exit $fail")


def test_runner_job_egress_confined():
    """A job on galaxy reaches DNS, the forge, GitHub and the Go proxy, and times out on every cluster, LAN
    and router target in the canary matrix (galaxy netpol B2, §9.3)."""
    branch = None
    try:
        branch, sha = push_probe_workflow(FORGE_BOT_REPO, "galaxy", _egress_script())
        assert wait_for(lambda: _settled(FORGE_BOT_REPO, sha) is not None, timeout=CYCLE_WAIT), \
            f"egress probe run did not finish within {CYCLE_WAIT} s"
        assert _settled(FORGE_BOT_REPO, sha) == ["success"]
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


@pytest.mark.parametrize("repo", [FORGE_BOT_REPO, CI_DISPATCH_REPO])
def test_workflow_triggers_and_pins(repo):                        # Success 17 (static)
    # forge-bot and ci-dispatch share one CI shape, the galaxy runner, the org REGISTRY_TOKEN and the Go cache:
    # each runs on pushes to main, v* tags and pull requests only, on galaxy only, and every action it uses is
    # pinned to a full commit SHA.
    r = requests.get(f"{FORGE}/{repo}/raw/branch/main/.forgejo/workflows/ci.yaml", timeout=20)
    r.raise_for_status()                                          # main only: ci-dispatch's v1 merged (v0.1.0)
    wf = yaml.safe_load(r.text)
    on = wf[True] if True in wf else wf["on"]                     # PyYAML reads a bare `on:` key as True
    assert set(on) == {"push", "pull_request"} and on["push"] == {"branches": ["main"], "tags": ["v*"]}
    assert wf["jobs"] and all(j["runs-on"] == "galaxy" for j in wf["jobs"].values())
    uses = [s["uses"] for j in wf["jobs"].values() for s in j["steps"] if "uses" in s]
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses


# Reports the registry credentials (`"auths"`) in any config.json under /work, then find's own exit status.
# `-exec grep -l ... {} +` keeps find's and grep's errors on stderr (an unreadable directory or file is no
# silent pass), and find exits 1 when grep matched nothing, so 0 and 1 are both a clean run. The control
# line proves grep runs and the pattern survives the quoting.
REGISTRY_SCAN = r"""printf '%s\n' '{"auths":{}}' | grep -cF '"auths"'
find /work -name config.json -type f -exec grep -lF '"auths"' {} +
echo "scan-exit=$?"
"""
BUSY = {"waiting", "running", "blocked"}


def _runner_busy() -> list[str]:
    """Actions tasks of the repos the shared galaxy runner serves that are queued or running right now."""
    busy = []
    for repo in (FORGE_BOT_REPO, CI_DISPATCH_REPO):
        r = forge_api("GET", f"/api/v1/repos/{repo}/actions/tasks", params={"limit": 50})
        r.raise_for_status()
        busy += [f"{repo}#{t['id']}:{t['status']}" for t in r.json()["workflow_runs"] if t["status"] in BUSY]
    return busy


def _scan_runner_volume() -> list[str]:
    """One snapshot of /work: the config.json files holding registry credentials. Any scan error fails."""
    r = kube("-n", "forgejo-runner", "exec", "deploy/forgejo-runner", "--", "sh", "-c", REGISTRY_SCAN)
    assert r.returncode == 0, f"exec failed (exit {r.returncode}): {r.stderr.strip()[:200]}"
    assert r.stderr.strip() == "", f"the scan reported errors (a path it could not read?): {r.stderr.strip()[:300]}"
    lines = r.stdout.split()
    assert lines[0] == "1", f"control did not match: {lines[:1]}"
    assert lines[-1] in ("scan-exit=0", "scan-exit=1"), f"scan failed: {lines[-1]}"
    return lines[1:-1]


@galaxy_only
def test_no_registry_credential_left_on_runner():                 # Review Focus 4
    # ci.yaml logs in with DOCKER_CONFIG=$(mktemp -d) under TMPDIR=/work/tmp, on the shared PVC, and
    # removes it on EXIT (pre-flight #6). Look at every config.json, not only paths that say "docker".
    # While forge-bot or ci-dispatch has an image job in flight, the credential is legitimately there for
    # the job's length, so a hit is retried (bounded: 15 x 20 s) only while one of their tasks is queued or
    # running. A hit with the runner idle fails at once; one that outlasts the window fails too.
    found, busy = [], []
    for _ in range(15):
        found = _scan_runner_volume()
        if not found:
            return
        busy = _runner_busy()
        if not busy:
            found = _scan_runner_volume()                         # the job may have ended and cleaned up since the scan
            break
        time.sleep(20)
    assert found == [], f"registry credentials left on the runner volume in: {found} (busy tasks: {busy})"
