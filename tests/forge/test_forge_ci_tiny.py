"""Acceptance for ci-dispatch and the `tiny` runner class (luma-homeops plan 2026-11-04-runner-classes-phase-0-1,
Task 16), written before the deploy: a member's `runs-on: tiny` job runs in a hardened, egress-confined,
single-use pod on galaxy, nothing outlives it, and the caps and holds show in the usage API.

Skips, with a reason, until ci-dispatch is deployed AND someone asks for the run:

    CI_TINY_ACCEPTANCE=1 nix develop --command pytest tests/forge/test_forge_ci_tiny.py -v

The run needs the `ci-dispatch` StatefulSet ready in namespace ci-dispatch and `tiny` set to `on`. These tests
start real jobs on galaxy, so run one suite at a time. The dispatcher launches one `tiny` job at a time
(global tiny_concurrent 1), so the file takes a while.

Every repo the tests make is named ci-tiny-acc-<hex8> and carries MARK as its description. A start-of-run sweep
and each test's teardown delete only those repos, the `ci-tiny-<job>-*` runners and the ci-tiny Jobs of the
keys the test itself saw, best effort: a failing teardown step never stops the next one. Member accounts go
with the forge_user fixture. Tokens are bound before an assert and never put in one (the guard test).
"""
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import warnings

import pytest

from ci_helpers import (DISPATCH_NS, TINY_NS, ci_token, delete_runner, forge_api_paged, job_key, kube_bytes,
                        list_jobs, push_workflow, run_status, runner_rows, tiny_leftovers, tiny_pods, usage,
                        usage_raw, usage_token, wait_status)
from conftest import _load_env
from forge_helpers import (FORGE, FORGE_SECRETS, LUMA, delete_branch, forge_api, forge_login, galaxy_only, kube,
                           wait_for)

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.environ.get("CI_TINY_ACCEPTANCE") != "1",
                                 reason="ci-dispatch acceptance: set CI_TINY_ACCEPTANCE=1 once ci-dispatch is deployed")]

MARK = "ci-tiny acceptance (realliance/sso tests)"
_REPO = re.compile(r"^ci-tiny-acc-[0-9a-f]{8}$")
CLASS_LABELS = ["tiny", "small", "medium", "large", "docker"]    # D13: the listing query from phase 1 on
MATRIX = LUMA / "cluster/netpol-canary/matrix.txt"
CONNECT_JS = LUMA / "scripts/netpol-connect.js"


@pytest.fixture(scope="module", autouse=True)
def _deployed():
    """Skip (never fail) while ci-dispatch is not running; sweep an earlier run's leftovers at the start."""
    try:
        r = kube("-n", DISPATCH_NS, "get", "statefulset", "ci-dispatch", "-o", "json", "--ignore-not-found",
                 timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        pytest.skip(f"ci-dispatch acceptance: cannot reach galaxy with kubectl ({type(e).__name__})")
    if r.returncode != 0:
        pytest.skip(f"ci-dispatch acceptance: kubectl cannot read {DISPATCH_NS} (exit {r.returncode})")
    if not r.stdout.strip():
        pytest.skip(f"ci-dispatch acceptance: StatefulSet {DISPATCH_NS}/ci-dispatch does not exist (not deployed yet)")
    if json.loads(r.stdout).get("status", {}).get("readyReplicas", 0) < 1:
        pytest.skip(f"ci-dispatch acceptance: StatefulSet {DISPATCH_NS}/ci-dispatch has no ready replica")
    _sweep_repos()
    yield
    _sweep_repos()


def _sweep_repos() -> None:
    """Delete forgejo-admin's repos that are ours: private, named ci-tiny-acc-<hex8>, marked."""
    try:
        for repo in forge_api_paged("/api/v1/users/forgejo-admin/repos"):
            if repo["private"] and _REPO.match(repo["name"]) and repo.get("description") == MARK:
                forge_api("DELETE", f"/api/v1/repos/{repo['full_name']}")
    except Exception:                                                     # noqa: BLE001 - best effort
        pass


class Tracker:
    """What one test made, so its teardown can remove exactly that."""

    def __init__(self) -> None:
        self.repos: list[str] = []
        self.keys: set[str] = set()
        self.job_ids: set[int] = set()

    def repo(self, owner: str | None = None, *, private: bool = False) -> dict:
        """A new marked repo with a `main` branch, owned by `owner` (through sudo) or forgejo-admin."""
        r = forge_api("POST", "/api/v1/user/repos", sudo=owner, json={
            "name": f"ci-tiny-acc-{secrets.token_hex(4)}", "private": private or owner is None,
            "auto_init": True, "default_branch": "main", "description": MARK})
        r.raise_for_status()
        info = r.json()
        self.repos.append(info["full_name"])
        return info

    def watch(self, repo_id: int, classes=("tiny",)) -> list[dict]:
        """The repo's jobs in the dispatcher's listing now; remembers their keys for the teardown."""
        jobs = [j for j in list_jobs(list(classes), ci_token()) if j["repo_id"] == repo_id]
        for j in jobs:
            self.keys.add(job_key(j))
            self.job_ids.add(j["id"])
        return jobs

    def cleanup(self) -> None:
        steps = [lambda r=r: forge_api("DELETE", f"/api/v1/repos/{r}") for r in self.repos]
        steps += [lambda k=k: kube("-n", TINY_NS, "delete", "job", "-l", f"ci-dispatch/key={k}",
                                   "--ignore-not-found", "--wait=false", timeout=60) for k in self.keys]

        def runners() -> None:
            tok = ci_token()
            for row in runner_rows(tok, visible=True):
                if any(row["name"].startswith(f"ci-tiny-{k}-") for k in self.keys):
                    delete_runner(row["id"], tok)

        for step in [*steps, runners]:
            try:
                step()
            except Exception:                                             # noqa: BLE001 - best effort
                pass


@pytest.fixture
def tracker():
    t = Tracker()
    yield t
    t.cleanup()


@pytest.fixture
def member(forge_user):
    """A throwaway Realliance member (write on the shared repos, but a plain user for `tiny`): the User, its
    Forgejo id and its signed-in session."""
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    session = forge_login(u)
    uid = forge_api("GET", f"/api/v1/users/{u.name}").json()["id"]
    return u, uid, session


def _probe(repo: dict, script: str, *, runs_on="tiny", env: dict | None = None) -> tuple[str, str]:
    """Push a one-job workflow whose single `sh` step runs `script`; returns (branch, sha)."""
    step = {"run": script, "shell": "sh", **({"env": env} if env else {})}
    return push_workflow(repo["full_name"], {"jobs": {"probe": {"runs-on": runs_on, "steps": [step]}}})


def _wait_success(tracker: Tracker, repo: dict, sha: str, timeout: float = 300) -> bool:
    """Wait for the run of `sha` to reach `success`, recording the job's key while it waits or runs."""
    def done() -> bool:
        tracker.watch(repo["id"])
        return run_status(repo["full_name"], sha) == "success"

    return wait_for(done, timeout, every=3)


def _run_tiny_job(tracker: Tracker, repo: dict, script: str, *, env=None, timeout=300) -> bool:
    """Push the probe and wait for `success`; the key it saw is in tracker.keys."""
    branch, sha = _probe(repo, script, env=env)
    try:
        return _wait_success(tracker, repo, sha, timeout)
    finally:
        delete_branch(repo["full_name"], branch)


def _wait_launched(tracker: Tracker, repo: dict, before: set[str], timeout: float = 120) -> bool:
    """Positive control for the leftover checks: the dispatcher has made a Job, Pod, Secret or runner for a
    job of this repo that was not there `before`. Polls every second, so it can act before the pickup."""
    def launched() -> bool:
        tracker.watch(repo["id"])
        new = tracker.keys - before
        return bool(new) and bool(tiny_leftovers(new))

    return wait_for(launched, timeout, every=1)


# --- a member's job runs ------------------------------------------------------------------------------------
def test_member_repo_runs_tiny(member, tracker):
    u, uid, _ = member
    repo = tracker.repo(u.name)
    ok = _run_tiny_job(tracker, repo, "echo hello from tiny")
    assert ok, f"the tiny probe in {repo['full_name']} did not reach success within 5 min"
    doc = usage(uid)
    assert doc["owner_id"] == uid
    assert doc["tiny"]["jobs_this_period"] == 1


HARDENED = """\
set -eu
test "$(id -u)" = 1000
test "$(id -g)" = 1000
root_opts=$(awk '$2 == "/" {o = $4} END {print o}' /proc/mounts)
case ",$root_opts," in *,ro,*) ;; *) echo "root is mounted: $root_opts" >&2; exit 1;; esac
grep -q '^[^ ]* /work tmpfs ' /proc/mounts
mkdir -p "$HOME"
touch "$HOME/.ci-tiny-rw" && test -w /work
test "$(awk '/^CapEff:/ {print $2}' /proc/self/status)" = 0000000000000000
test "$(awk '/^Seccomp:/ {print $2}' /proc/self/status)" = 2
test "$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)" = 1
test -z "${KUBERNETES_SERVICE_HOST:-}"
size_kb=$(df -k /work | awk 'NR==2 {print $2}')
test "$size_kb" -le 1048576
test "$HOME" = /work/home
test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
test ! -e /var/run/secrets/kubernetes.io
test ! -S /var/run/docker.sock
test ! -S /run/docker.sock
test -z "${DOCKER_HOST:-}"
echo hardened
"""


def test_tiny_job_hardened(member, tracker):
    u, _, _ = member
    repo = tracker.repo(u.name)
    ok = _run_tiny_job(tracker, repo, HARDENED)
    assert ok, "a hardening check failed inside the tiny job (ids, root mount ro, /work tmpfs <= 1 GiB and writable, caps, seccomp, no-new-privs, service links, SA token, Docker socket)"
    assert tracker.keys, "no key was seen: a tiny pod may not have run the job"


# --- egress ----------------------------------------------------------------------------------------------
def _reachable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=6).close()
        return True
    except OSError:
        return False


def _matrix_rows() -> list[tuple[str, str, str]]:
    """(expect, host, port) for the `all` rows of the canary matrix, minus $HOST_IP, plus the tiny extras."""
    rows = []
    for line in MATRIX.read_text().splitlines():
        f = line.split()
        if not f or f[0].startswith("#") or f[1] != "all":
            continue
        expect, _, host, port = f[:4]
        if host == "$HOST_IP":
            continue
        if host == "$WAN_IP":
            host = socket.gethostbyname("git.realliance.net")
            if not ipaddress.ip_address(host).is_global:      # split DNS on the LAN would test another target
                pytest.skip(f"git.realliance.net resolves to a non-public address here ({host})")
        rows.append((expect, host, port))
    return rows + [("dropped", "github.com", "22"), ("dropped", "1.1.1.1", "853"), ("open", "1.1.1.1", "80")]


EGRESS = """\
set -u
rows_file="${TMPDIR:-/work}/rows"
printf '%s\\n' "$ROWS" > "$rows_file"
bad=0
while read -r want host port; do
  [ -n "$want" ] || continue
  if [ "$want" = dns ]; then got=$(node -e "$CONNECT_JS" dns "$host" || true); need=open
  else got=$(node -e "$CONNECT_JS" tcp "$host" "$port" || true); need=$([ "$want" = dropped ] && echo timeout || echo open); fi
  if [ "$got" = "$need" ]; then echo "PASS $want $got $host:$port"; else echo "FAIL $want $got $host:$port"; bad=1; fi
done < "$rows_file"
git ls-remote --exit-code "$FORGE_REPO" HEAD > /dev/null || { echo "FAIL git ls-remote forge"; bad=1; }
git ls-remote --exit-code https://github.com/octocat/Hello-World.git HEAD > /dev/null || { echo "FAIL git ls-remote github"; bad=1; }
exit "$bad"
"""


def test_tiny_job_egress_confined(member, tracker):
    # Without these two answering from here, a timeout in the job would prove nothing about the policy.
    if not _reachable("github.com", 22) or not _reachable("1.1.1.1", 853):
        pytest.skip("github.com:22 or 1.1.1.1:853 does not answer from this machine: a drop in the job would prove nothing")
    u, _, _ = member
    repo = tracker.repo(u.name)
    rows = "\n".join(" ".join(r) for r in _matrix_rows())
    env = {"ROWS": rows, "CONNECT_JS": CONNECT_JS.read_text(), "FORGE_REPO": f"{FORGE}/{repo['full_name']}.git"}
    ok = _run_tiny_job(tracker, repo, EGRESS, env=env, timeout=420)
    assert ok, "a row of the egress matrix, or git ls-remote, did not match inside the tiny job (the run log lists each row)"
    assert tracker.keys, "no key was seen: a tiny pod may not have run the job"


# --- nothing outlives the job ----------------------------------------------------------------------------
def _cancel(session, repo: dict, sha: str) -> int:
    """Cancel the run through the web route, as the member (Forgejo 15 checks Fetch metadata, not CSRF tokens)."""
    run = next(iter(forge_api("GET", f"/api/v1/repos/{repo['full_name']}/actions/runs",
                              params={"head_sha": sha}).json()["workflow_runs"]))
    index = run.get("index_in_repo") or run["id"]
    return session.post(f"{FORGE}/{repo['full_name']}/actions/runs/{index}/cancel", timeout=30).status_code


def test_nothing_outlives_the_job(member, tracker):  # Review Focus 1
    """Half one: after a normal run nothing is left (with a mid-run positive control that the check can
    see the pod). Half two: a run cancelled once the dispatcher has launched for it (a Job, Pod, Secret or
    runner exists) leaves nothing within the bound. The pod may already have picked the job up when the
    cancel lands, which is just as worth proving; if the dispatcher never launches in time the test fails
    at the positive control rather than passing for nothing."""
    u, uid, session = member
    repo = tracker.repo(u.name)
    full = repo["full_name"]
    branch, sha = _probe(repo, "sleep 20")
    try:
        launched = _wait_launched(tracker, repo, set())
        assert launched, "no Job, Pod, Secret or runner was ever seen for the probe, so the leftover check proves nothing"
        done = _wait_success(tracker, repo, sha)
        assert done, "the tiny probe did not reach success"
    finally:
        delete_branch(full, branch)
    keys = set(tracker.keys)
    time.sleep(60)
    left = tiny_leftovers(keys)
    assert left == [], f"60 s after the run ended, ci-tiny or the forge still holds: {left}"

    before = set(tracker.keys)
    branch, sha = _probe(repo, "sleep 120")
    try:
        launched = _wait_launched(tracker, repo, before, timeout=90)
        assert launched, "the dispatcher made nothing for the second probe in 90 s, so there is nothing to cancel after"
        status = _cancel(session, repo, sha)
        assert status < 400, f"cancelling the run failed: HTTP {status}"
        assert wait_status(full, sha, "cancelled", timeout=60), "the run did not end as cancelled"
        cancelled_keys = tracker.keys - before
        gone = wait_for(lambda: tiny_leftovers(cancelled_keys) == [], 6 * 60, every=10)
        left = tiny_leftovers(cancelled_keys)
        assert gone, f"a cancelled job left behind: {left}"
    finally:
        delete_branch(full, branch)


# --- concurrency and caps ------------------------------------------------------------------------------------
def test_owner_runs_one_at_a_time(member, tracker):
    u, _, _ = member
    repo = tracker.repo(u.name)
    full = repo["full_name"]
    first = _probe(repo, "sleep 30")
    second = _probe(repo, "sleep 30")
    shas = {"first": first[1], "second": second[1]}
    seen = {k: {} for k in shas}
    most_running = 0
    deadline = time.monotonic() + 15 * 60
    try:
        while time.monotonic() < deadline:
            now = {k: run_status(full, s) for k, s in shas.items()}
            for k, st in now.items():
                if st in ("running", "success", "failure", "cancelled"):
                    seen[k].setdefault(st, time.time())
            most_running = max(most_running, sum(1 for st in now.values() if st == "running"))
            if all(st in ("success", "failure", "cancelled") for st in now.values()):
                break
            tracker.watch(repo["id"])
            time.sleep(2)
        assert all("success" in seen[k] for k in seen), "both probes should have succeeded"
        assert most_running == 1, f"{most_running} of the owner's probes ran at the same moment"
        early, late = sorted(seen, key=lambda k: seen[k]["running"])
        assert seen[late]["running"] >= seen[early]["success"] - 4, "the second probe started before the first ended"
    finally:
        for branch in (first[0], second[0]):
            delete_branch(full, branch)


def _holds(owner_id: int, repo_id: int) -> list[dict]:
    return [h for h in usage(owner_id)["holds"] if h["repo_id"] == repo_id]


RESERVE_MINUTES = 20          # a tiny job reserves its hard stop (Task 15: forgejo-admin's whole day)


def test_owner_minutes_cap_holds(tracker):  # D11
    """forgejo-admin may run 20 tiny minutes a day, and one job reserves all 20. The gate checks owner
    concurrency first (a second job waits as `owner-busy` while the first runs) and the minutes second. So:
    run A to completion; whatever it was charged (at least 1 minute, a Task 12 rule) leaves less than one
    reservation, and B holds as `owner-limit`. If A itself would already be held (minutes used today), assert
    that and skip the rest. Either way the account stays capped until 00:00 UTC."""
    admin = forge_api("GET", "/api/v1/users/forgejo-admin").json()
    before = usage(admin["id"])["tiny"]
    used, per_day = before["minutes_today"], before["minutes_per_day"]
    a_held = used + RESERVE_MINUTES > per_day
    repo = tracker.repo(None)
    full = repo["full_name"]
    a_branch, a_sha = _probe(repo, "sleep 20")
    try:
        if a_held:
            held = wait_for(lambda: any(h["reason"] == "owner-limit" and h["class"] == "tiny"
                                        for h in _holds(admin["id"], repo["id"])), 180, every=5)
            assert held, "forgejo-admin is already over its tiny minutes, yet job A did not show as an owner-limit hold"
            assert run_status(full, a_sha) != "success", "the held job ran"
            pytest.skip(f"forgejo-admin has used {used} of {per_day} tiny minutes today: asserted that job A is held, "
                        "the launch half runs tomorrow (after 00:00 UTC)")
        started = _wait_success(tracker, repo, a_sha)
        assert started, "the first job did not run to success"
        # Job A's charge is recorded when the dispatcher settles it, a loop after Forgejo says success. B
        # must not be listed before that, or it could launch instead of hold.
        charged = wait_for(lambda: usage(admin["id"])["tiny"]["minutes_today"] > used, 120, every=3)
        assert charged, "job A's minutes never showed in forgejo-admin's usage (is a short job charged at least 1 minute?)"
        b_branch, b_sha = _probe(repo, "echo second")
        held = wait_for(lambda: any(h["reason"] == "owner-limit" and h["class"] == "tiny"
                                    for h in _holds(admin["id"], repo["id"])), 180, every=5)
        assert held, "after job A, the second job never showed as an owner-limit hold (is a short job charged at least 1 minute?)"
        assert run_status(full, b_sha) != "success", "the held job ran"
        warnings.warn("forgejo-admin is now capped for tiny until 00:00 UTC; rerun this test tomorrow for the launch half")
    finally:
        tracker.watch(repo["id"])
        for branch in (a_branch, locals().get("b_branch")):
            if branch:
                delete_branch(full, branch)


def test_label_combo_holds(member, tracker):
    u, uid, _ = member
    repo = tracker.repo(u.name)
    wf = {"jobs": {"combo": {"runs-on": ["tiny", "docker"], "steps": [{"run": "echo no", "shell": "sh"}]},
                   "small": {"runs-on": "small", "steps": [{"run": "echo no", "shell": "sh"}]}}}
    branch, sha = push_workflow(repo["full_name"], wf)
    try:
        def jobs():
            return {j["name"]: j for j in tracker.watch(repo["id"], CLASS_LABELS)}

        assert wait_for(lambda: {"combo", "small"} <= jobs().keys(), 120, every=3), "the jobs never reached the listing"
        combo = jobs()["combo"]
        held = wait_for(lambda: any(h["job_id"] == combo["id"] and h["reason"] == "label"
                                    for h in _holds(uid, repo["id"])), 120, every=5)
        assert held, "runs-on [tiny, docker] never showed as a label hold"
        time.sleep(30)                      # neither may start in the meantime
        holds = _holds(uid, repo["id"])
        assert {h["job_id"] for h in holds} == {combo["id"]}, "only the [tiny, docker] job should hold (small waits)"
        now = jobs()
        assert {j["status"] for j in now.values()} == {"waiting"}, "one of the jobs left `waiting`"
        assert run_status(repo["full_name"], sha) not in ("success", "failure")
        launched = [p for p in tiny_pods() if p["metadata"].get("labels", {}).get("ci-dispatch/key") in tracker.keys]
        assert launched == [], "a pod was launched for a held job"
    finally:
        delete_branch(repo["full_name"], branch)


# --- usage API -------------------------------------------------------------------------------------------------
def _all_keys(x) -> set[str]:
    if isinstance(x, dict):
        return set(x) | {k for v in x.values() for k in _all_keys(v)}
    if isinstance(x, list):
        return {k for v in x for k in _all_keys(v)}
    return set()


def test_usage_api_auth_and_ids(member, tracker):
    u, uid, _ = member
    repo = tracker.repo(u.name)
    branch, _ = push_workflow(repo["full_name"], {"jobs": {"combo": {
        "runs-on": ["tiny", "docker"], "steps": [{"run": "echo no", "shell": "sh"}]}}})     # gives the body a hold
    try:
        assert wait_for(lambda: bool(_holds(uid, repo["id"])), 180, every=5), "no hold to look at"
        assert usage_raw(uid).status_code == 401
        wrong = secrets.token_hex(16)
        assert usage_raw(uid, wrong).status_code == 401
        tok = usage_token()
        r = usage_raw(uid, tok)
        assert r.status_code == 200
        body = r.json()
        assert body["owner_id"] == uid
        text = r.text
        assert u.name not in text and repo["name"] not in text, "the body names the owner or the repo"
        assert not {k for k in _all_keys(body) if "login" in k or "name" in k or k in ("owner", "repo")}
        assert all(isinstance(h["repo_id"], int) and isinstance(h["job_id"], int) for h in body["holds"])
        rj = usage_raw(uid, tok, what="jobs")
        assert rj.status_code == 200
        jobs_text = rj.text
        assert u.name not in jobs_text and repo["name"] not in jobs_text, "the jobs list names the owner or the repo"
    finally:
        delete_branch(repo["full_name"], branch)


# --- the dispatcher's secrets stay out of the pod ----------------------------------------------------------
INSPECT = "cat /proc/1/environ; find /etc /work /creds -type f -exec cat {} +"


@galaxy_only
def test_dispatcher_secrets_not_in_tiny_pod(member, tracker):
    u, uid, _ = member
    repo = tracker.repo(u.name)
    nonce = secrets.token_hex(16)                     # not a secret: it proves the search can find a job's file
    script = 'printf %s "$NONCE" > /work/nonce.txt\nsleep 60'
    branch, sha = _probe(repo, script, env={"NONCE": nonce})
    out = b""
    try:
        def exec_in_pod() -> bool:
            nonlocal out
            for j in tracker.watch(repo["id"]):
                for p in tiny_pods(job_key(j)):
                    if p["status"].get("phase") == "Running":
                        r = kube_bytes("-n", TINY_NS, "exec", p["metadata"]["name"], "-c", "runner", "--",
                                       "sh", "-c", INSPECT)
                        out = r.stdout
            return nonce.encode() in out              # positive control: the job's own file is in the output

        assert wait_for(exec_in_pod, 120, every=3), "never saw the job's nonce in the pod, so the search proves nothing"
        # What a pod spec carries (env, args) is searched too, not only the files and PID 1's environment.
        spec = kube_bytes("-n", TINY_NS, "get", "job,pod", "-o", "json").stdout
        haystack = out + b"\n" + spec
        env = {**_load_env(FORGE_SECRETS), **os.environ}
        names = ("CI_DISPATCH_FORGEJO_TOKEN", "CI_DISPATCH_USAGE_TOKEN", "FORGEJO_ADMIN_TOKEN", "FORGE_BOT_FORGEJO_TOKEN")
        values = [env[n] for n in names if len(env.get(n, "")) >= 16]
        n_tokens = len(values)                        # a count: pytest would print a list of tokens
        assert n_tokens >= 2, "too few of the dispatcher's tokens are available locally to search for"
        old = os.umask(0o077)
        try:
            fd, path = tempfile.mkstemp(prefix="ci-tiny-needles-")
        finally:
            os.umask(old)
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(values) + "\n")
            found = subprocess.run(["grep", "-F", "-q", "-f", path], input=haystack, capture_output=True).returncode
        finally:
            os.unlink(path)                           # at once
        assert found == 1, "grep failed" if found > 1 else "a dispatcher or admin token is inside the tiny pod"
    finally:
        delete_branch(repo["full_name"], branch)
