"""Acceptance for the paid runner classes `small` and `medium` (luma-homeops plan 2026-11-05-runner-classes-phase-2,
Task 8), written before the deploy: a member's paid job runs in a fresh Azure Container Instances group that
nothing shares, the owner's dollar limit pays for it, nothing outlives it, and the credentials stay out of
the group definition and the job.

Skips, with a reason, until ci-dispatch v0.2.0 serves paid usage AND someone asks for the run:

    CI_PAID_ACCEPTANCE=1 nix develop --command pytest tests/forge/test_forge_ci_paid.py -v

Needs `az` logged in with read access to rg-realliance-ci, the `ci-dispatch` StatefulSet ready, `small` and
`medium` set to `on`, and forgejo-admin's paid limit set to $0.15 (for the cap test). These tests start
real, billed jobs, so run one suite at a time. A paid job is sized to cost under a cent a minute.

Every repo the tests make is named ci-paid-acc-<hex8> and carries MARK as its description; a start-of-run
sweep and each test's teardown delete only those, the runners and groups of the keys the test itself saw,
best effort. Tokens are bound before an assert and never put in one (the guard test); the secret checks
compare sha256 hashes, so no secret reaches argv, a log or a message.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from decimal import Decimal

import pytest

from ci_helpers import (CI_GROUP, DISPATCH_NS, PAID_CLASSES, aci_group_names, az, ci_token, delete_runner,
                        job_key, job_log_text, list_jobs, paid_leftovers, push_workflow,
                        run_status, runner_rows, usage, wait_status)
from conftest import _load_env
from forge_helpers import FORGE, FORGE_SECRETS, delete_branch, forge_api, forge_login, kube, wait_for

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.environ.get("CI_PAID_ACCEPTANCE") != "1",
                                 reason="paid runner-class acceptance: set CI_PAID_ACCEPTANCE=1 once ci-dispatch v0.2.0 is deployed")]

MARK = "ci-paid acceptance (realliance/sso tests)"
_REPO = re.compile(r"^ci-paid-acc-[0-9a-f]{8}$")
CLASS_LABELS = ["tiny", "small", "medium", "large", "docker"]    # the listing query (D13)
RUN_TIMEOUT = 8 * 60
PICKUP_TIMEOUT = 6 * 60                                          # the dispatcher's pickup timeout
RESERVATION = Decimal("0.078")                                   # a `small` reservation: 78_000 micro-dollars
ADMIN_CAP = Decimal("0.15")
# sleep long enough that the charge is at least half a cent, so the cents-rounded `used_usd` is not "0.00"
CHARGED_SLEEP = {"small": 200, "medium": 120}


@pytest.fixture(scope="module", autouse=True)
def _deployed():
    """Skip (never fail) while paid classes are not deployed; sweep an earlier run's leftovers at the start."""
    if shutil.which("az") is None:
        pytest.skip("paid acceptance: az is not on PATH (run inside nix develop)")
    try:
        r = kube("-n", DISPATCH_NS, "get", "statefulset", "ci-dispatch", "-o", "json", "--ignore-not-found",
                 timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        pytest.skip(f"paid acceptance: cannot reach galaxy with kubectl ({type(e).__name__})")
    if r.returncode != 0:
        pytest.skip(f"paid acceptance: kubectl cannot read {DISPATCH_NS} (exit {r.returncode})")
    if not r.stdout.strip():
        pytest.skip(f"paid acceptance: StatefulSet {DISPATCH_NS}/ci-dispatch does not exist (not deployed yet)")
    if json.loads(r.stdout).get("status", {}).get("readyReplicas", 0) < 1:
        pytest.skip(f"paid acceptance: StatefulSet {DISPATCH_NS}/ci-dispatch has no ready replica")
    admin = forge_api("GET", "/api/v1/users/forgejo-admin").json()["id"]
    try:
        served = "paid" in usage(admin)
    except Exception:                                                     # noqa: BLE001 - any failure is "not yet"
        served = False
    if not served:
        pytest.skip("paid acceptance: the usage API does not serve paid numbers yet (v0.2.0 is not deployed)")
    _sweep_repos()
    yield
    _sweep_repos()


def _sweep_repos() -> None:
    """Delete forgejo-admin's and the members' repos that are ours: named ci-paid-acc-<hex8>, marked."""
    try:
        for repo in _search_repos():
            if _REPO.match(repo["name"]) and repo.get("description") == MARK:
                forge_api("DELETE", f"/api/v1/repos/{repo['full_name']}")
    except Exception:                                                     # noqa: BLE001 - best effort
        pass


def _search_repos() -> list[dict]:
    out, page = [], 1
    while True:
        r = forge_api("GET", "/api/v1/repos/search", params={"q": "ci-paid-acc-", "page": page, "limit": 50})
        r.raise_for_status()
        batch = r.json()["data"]
        out += batch
        if len(batch) < 50:
            return out
        page += 1


class Tracker:
    """What one test made, so its teardown can remove exactly that."""

    def __init__(self) -> None:
        self.repos: list[str] = []
        self.keys: set[str] = set()

    def repo(self, owner: str | None = None) -> dict:
        """A new marked repo with a `main` branch: public and owned by `owner` (through sudo), or forgejo-admin's
        private one."""
        r = forge_api("POST", "/api/v1/user/repos", sudo=owner, json={
            "name": f"ci-paid-acc-{secrets.token_hex(4)}", "private": owner is None,
            "auto_init": True, "default_branch": "main", "description": MARK})
        r.raise_for_status()
        info = r.json()
        self.repos.append(info["full_name"])
        return info

    def watch(self, repo_id: int) -> list[dict]:
        """The repo's jobs in the dispatcher's listing now; remembers their keys for the teardown."""
        jobs = [j for j in list_jobs(CLASS_LABELS, ci_token()) if j["repo_id"] == repo_id]
        self.keys.update(job_key(j) for j in jobs)
        return jobs

    def cleanup(self) -> None:
        def runners() -> None:
            tok = ci_token()
            for row in runner_rows(tok, visible=True):
                if any(row["name"].startswith(f"ci-{c}-{k}-") for c in PAID_CLASSES for k in self.keys):
                    delete_runner(row["id"], tok)

        def groups() -> None:
            for name in aci_group_names():
                if any(name.startswith(f"ci-{c}-{k}-") for c in PAID_CLASSES for k in self.keys):
                    az("container", "delete", "-g", CI_GROUP, "-n", name, "--yes", "-o", "none", timeout=300)

        steps = [lambda r=r: forge_api("DELETE", f"/api/v1/repos/{r}") for r in self.repos]
        for step in [*steps, runners, groups]:
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
    """A throwaway Realliance member: the User, its Forgejo id and its signed-in session."""
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    session = forge_login(u)
    uid = forge_api("GET", f"/api/v1/users/{u.name}").json()["id"]
    return u, uid, session


def _probe(repo: dict, script: str, *, runs_on="small") -> tuple[str, str]:
    """Push a one-job workflow whose single `sh` step runs `script`; returns (branch, sha)."""
    step = {"run": script, "shell": "sh"}
    return push_workflow(repo["full_name"], {"jobs": {"probe": {"runs-on": runs_on, "steps": [step]}}})


def _wait_success(tracker: Tracker, repo: dict, sha: str, timeout: float = RUN_TIMEOUT) -> bool:
    def done() -> bool:
        tracker.watch(repo["id"])
        return run_status(repo["full_name"], sha) == "success"

    return wait_for(done, timeout, every=3)


def _run_job(tracker: Tracker, repo: dict, script: str, *, runs_on="small", timeout: float = RUN_TIMEOUT) -> bool:
    branch, sha = _probe(repo, script, runs_on=runs_on)
    try:
        return _wait_success(tracker, repo, sha, timeout)
    finally:
        delete_branch(repo["full_name"], branch)


def _cancel(session, repo: dict, sha: str) -> int:
    """Cancel the run through the web route, as the member."""
    run = next(iter(forge_api("GET", f"/api/v1/repos/{repo['full_name']}/actions/runs",
                              params={"head_sha": sha}).json()["workflow_runs"]))
    index = run.get("index_in_repo") or run["id"]
    return session.post(f"{FORGE}/{repo['full_name']}/actions/runs/{index}/cancel", timeout=30).status_code


def _holds(owner_id: int, repo_id: int) -> list[dict]:
    return [h for h in usage(owner_id)["holds"] if h["repo_id"] == repo_id]


def _group_of(keys: set[str], cls: str = "small") -> str | None:
    """The ACI group name made for one of `keys`, or None."""
    return next((n for n in aci_group_names() if any(n.startswith(f"ci-{cls}-{k}-") for k in keys)), None)


def _sums_to_limit(paid: dict) -> bool:
    """used + reserved + remaining == limit as decimals. Usage rounds used and reserved to cents first and
    floors remaining at 0, so the sum is exactly the limit whenever anything remains, and at least the limit
    when it does not (F21)."""
    used, reserved = Decimal(paid["used_usd"]), Decimal(paid["reserved_usd"])
    remaining, limit = Decimal(paid["remaining_usd"]), Decimal(paid["limit_usd"])
    total = used + reserved + remaining
    return total == limit if remaining > 0 else total >= limit


# --- a member's job runs ------------------------------------------------------------------------------------
def _runs_and_is_charged(member, tracker, cls: str) -> None:
    u, uid, _ = member
    repo = tracker.repo(u.name)
    ok = _run_job(tracker, repo, f"echo hello from {cls}; sleep {CHARGED_SLEEP[cls]}", runs_on=cls)
    assert ok, f"the {cls} probe in {repo['full_name']} did not reach success within 8 min"

    def settled() -> bool:
        p = usage(uid)["paid"]
        return p["classes"].get(cls, {}).get("jobs") == 1 and Decimal(p["reserved_usd"]) == 0

    assert wait_for(settled, 180, every=5), f"the {cls} job never settled: one job and reserved_usd 0.00"
    paid = usage(uid)["paid"]
    assert paid["classes"][cls]["jobs"] == 1
    assert {c for c, v in paid["classes"].items() if v["jobs"]} == {cls}, "one job per class, and only this class"
    assert Decimal(paid["used_usd"]) > 0, f"the {cls} job was not charged"
    assert Decimal(paid["classes"][cls]["used_usd"]) > 0


def test_member_repo_runs_small(member, tracker):
    _runs_and_is_charged(member, tracker, "small")


def test_member_repo_runs_medium(member, tracker):
    _runs_and_is_charged(member, tracker, "medium")


SHAPE = """\
set -eu
test "$(nproc)" = 2
mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
test "$mem_kb" -ge 7549747 && test "$mem_kb" -le 9227469
test "$(id -u)" = 0
test -z "${KUBERNETES_SERVICE_HOST:-}"
if env | cut -d= -f1 | grep -qx RUNNER_TOKEN; then echo "RUNNER_TOKEN is in env" >&2; exit 1; fi
test "$(stat -c %a /run/ci/token)" = 600
if curl -sS -m 5 -o /dev/null https://192.168.0.7; then echo "the LAN ingress answered" >&2; exit 1; fi
imds=$(curl -sS -m 5 -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' 2>/dev/null || true)
case "$imds" in *access_token*) echo "IMDS issued a token" >&2; exit 1;; esac
export GIT_TERMINAL_PROMPT=0
git ls-remote "$FORGE_URL" HEAD > /dev/null
git ls-remote https://github.com/actions/checkout HEAD > /dev/null
echo shape-ok
"""


def test_paid_job_shape(member, tracker):
    u, _, _ = member
    repo = tracker.repo(u.name)
    script = SHAPE.replace("$FORGE_URL", f"{FORGE}/{repo['full_name']}")
    ok = _run_job(tracker, repo, script)
    assert ok, ("a shape check failed inside the paid job (2 CPUs, 8 GiB +-10 %, root, no service links, no "
                "RUNNER_TOKEN, /run/ci/token 0600, LAN ingress and IMDS blocked, git reaches the forge and GitHub)")


# --- nothing outlives the job ----------------------------------------------------------------------------------
def test_paid_nothing_outlives_the_job(member, tracker):
    """Half one: 120 s after a normal run no group and no runner is left. Half two: a probe cancelled as soon as
    it shows in the dispatcher's listing (before any pickup) leaves nothing within the pickup timeout plus
    two polls."""
    u, _, session = member
    repo = tracker.repo(u.name)
    full = repo["full_name"]
    branch, sha = _probe(repo, "sleep 20")
    try:
        assert _wait_success(tracker, repo, sha), "the small probe did not reach success"
    finally:
        delete_branch(full, branch)
    keys = set(tracker.keys)
    n = len(keys)
    assert n >= 1, "no job key was seen, so the leftover check proves nothing"
    time.sleep(120)
    left = paid_leftovers(keys)
    assert left == [], f"120 s after the run ended, ACI or the forge still holds: {left}"

    before = set(tracker.keys)
    branch, sha = _probe(repo, "sleep 120")
    try:
        assert wait_for(lambda: bool(tracker.watch(repo["id"])), 120, every=1), "the probe never reached the listing"
        status = _cancel(session, repo, sha)
        assert status < 400, f"cancelling the run failed: HTTP {status}"
        assert wait_status(full, sha, "cancelled", timeout=60), "the run did not end as cancelled"
        cancelled = tracker.keys - before
        gone = wait_for(lambda: paid_leftovers(cancelled) == [], PICKUP_TIMEOUT + 2 * 30, every=10)
        left = paid_leftovers(cancelled)
        assert gone, f"a job cancelled before pickup left behind: {left}"
    finally:
        delete_branch(full, branch)


# --- the owner's dollar limit ----------------------------------------------------------------------------------
def test_owner_paid_cap_holds(tracker):
    """forgejo-admin is capped at $0.15, so two small reservations (0.156) do not fit together. A runs and
    sleeps 90 s; B holds `owner-limit` meanwhile. When A settles, B launches if the remaining dollars still
    cover one reservation (a decimal comparison, never a rounded string; F21), and otherwise stays held."""
    admin_id = forge_api("GET", "/api/v1/users/forgejo-admin").json()["id"]
    paid = usage(admin_id)["paid"]
    limit, remaining = Decimal(paid["limit_usd"]), Decimal(paid["remaining_usd"])
    if limit != ADMIN_CAP:
        pytest.skip(f"forgejo-admin's paid limit is ${limit}, not $0.15: set it to 0.15 for this test")
    a, b = tracker.repo(None), tracker.repo(None)
    a_branch, a_sha = _probe(a, "sleep 90")
    b_branch = None
    try:
        if remaining < Decimal("0.08"):
            held = wait_for(lambda: any(h["reason"] == "owner-limit" for h in _holds(admin_id, a["id"])), 180, every=5)
            assert held, "forgejo-admin has under $0.08 left, yet job A did not show as an owner-limit hold"
            assert run_status(a["full_name"], a_sha) != "success", "the held job ran"
            return
        assert wait_for(lambda: tracker.watch(a["id"]) and run_status(a["full_name"], a_sha) == "running",
                        RUN_TIMEOUT, every=3), "job A never started"
        b_branch, b_sha = _probe(b, "echo second")
        held = wait_for(lambda: any(h["reason"] == "owner-limit" and h["class"] == "small"
                                    for h in _holds(admin_id, b["id"])), 120, every=3)
        assert held, "while A ran, B never showed as an owner-limit hold (two reservations exceed $0.15)"
        assert run_status(b["full_name"], b_sha) != "success", "the held job ran"
        assert _wait_success(tracker, a, a_sha), "job A did not reach success"
        # A's charge lands when the dispatcher settles it, a loop after Forgejo says success.
        assert wait_for(lambda: Decimal(usage(admin_id)["paid"]["reserved_usd"]) == 0, 180, every=3), \
            "A's reservation never settled"
        left = Decimal(usage(admin_id)["paid"]["remaining_usd"])
        if left >= RESERVATION:
            assert wait_for(lambda: tracker.watch(b["id"]) and run_status(b["full_name"], b_sha) == "success",
                            RUN_TIMEOUT, every=5), f"${left} remains, yet B did not launch and succeed"
        else:
            time.sleep(60)
            assert any(h["reason"] == "owner-limit" for h in _holds(admin_id, b["id"])), \
                f"only ${left} remains, yet B no longer holds as owner-limit"
            assert run_status(b["full_name"], b_sha) != "success", "B ran with too little left"
    finally:
        tracker.watch(a["id"])
        tracker.watch(b["id"])
        for repo, branch in ((a, a_branch), (b, b_branch)):
            if branch:
                delete_branch(repo["full_name"], branch)


# --- label combinations -----------------------------------------------------------------------------------------
def test_label_combos_paid(member, tracker):
    u, uid, _ = member
    repo = tracker.repo(u.name)
    echo = [{"run": "echo no", "shell": "sh"}]
    wf = {"jobs": {"dock": {"runs-on": ["small", "docker"], "steps": echo},
                   "big": {"runs-on": "large", "steps": echo},
                   "two": {"runs-on": ["small", "medium"], "steps": echo}}}
    branch, sha = push_workflow(repo["full_name"], wf)
    try:
        def jobs():
            return {j["name"]: j for j in tracker.watch(repo["id"])}

        assert wait_for(lambda: {"dock", "big", "two"} <= jobs().keys(), 120, every=3), "the jobs never reached the listing"
        two = jobs()["two"]
        held = wait_for(lambda: any(h["job_id"] == two["id"] and h["reason"] == "label"
                                    for h in _holds(uid, repo["id"])), 120, every=5)
        assert held, "runs-on [small, medium] never showed as a label hold"
        time.sleep(30)                                  # none may start in the meantime
        assert {h["job_id"] for h in _holds(uid, repo["id"])} == {two["id"]}, \
            "only the [small, medium] job should hold ([small, docker] and large wait with no hold row)"
        assert {j["status"] for j in jobs().values()} == {"waiting"}, "one of the jobs left `waiting`"
        assert run_status(repo["full_name"], sha) not in ("success", "failure")
        assert _group_of(set(tracker.keys), "small") is None and _group_of(set(tracker.keys), "medium") is None, \
            "a group was launched for a job that must never run"
    finally:
        delete_branch(repo["full_name"], branch)


# --- usage numbers ----------------------------------------------------------------------------------------------
def test_usage_paid_numbers(member, tracker):
    u, uid, _ = member
    assert _sums_to_limit(usage(uid)["paid"]), "a fresh owner's used + reserved + remaining is not the limit"
    repo = tracker.repo(u.name)
    branch, sha = _probe(repo, "sleep 30")
    try:
        mid = {"seen": False}

        def during() -> bool:
            tracker.watch(repo["id"])
            doc = usage(uid)["paid"]
            assert _sums_to_limit(doc), "used + reserved + remaining is not the limit while a job runs"
            mid["seen"] = mid["seen"] or Decimal(doc["reserved_usd"]) > 0
            return run_status(repo["full_name"], sha) == "success"

        assert wait_for(during, RUN_TIMEOUT, every=4), "the probe did not reach success"
        assert mid["seen"], "reserved_usd never rose above 0.00 while the job ran"
    finally:
        delete_branch(repo["full_name"], branch)
    assert wait_for(lambda: Decimal(usage(uid)["paid"]["reserved_usd"]) == 0, 180, every=5), "the reservation never freed"
    doc = usage(uid)
    paid = doc["paid"]
    assert _sums_to_limit(paid), "after the job, used + reserved + remaining is not the limit"
    assert paid["classes"]["small"]["jobs"] == 1, "classes.small.jobs must count distinct jobs"
    assert doc["global"]["paid"] in ("open", "near-cap"), "global.paid is neither open nor near-cap"


# --- the runner credential and the dispatcher's secrets stay out ------------------------------------------------
HASH_TOKEN = r"""
hash_runs() {
  grep -oE '[A-Za-z0-9._~+/=-]{20,}' | while IFS= read -r run; do
    printf 'H:%s\n' "$(printf %s "$run" | sha256sum | cut -d' ' -f1)"
    case "$run" in *=*)
      printf 'H:%s\n' "$(printf %s "${run#*=}" | sha256sum | cut -d' ' -f1)";;
    esac
  done
}
"""
HEX64 = re.compile(r"^H:([0-9a-f]{64})$", re.M)


def _private_file(prefix: str, data: str) -> str:
    old = os.umask(0o077)
    try:
        fd, path = tempfile.mkstemp(prefix=prefix)
    finally:
        os.umask(old)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    return path


def _hashes(log: str) -> set[str]:
    return set(HEX64.findall(log))


def test_runner_credential_not_in_group_definition(member, tracker):  # Review Focus 4
    """The job prints sha256 of its runner credential (a 40-hex string) and sleeps. While it sleeps, the group
    definition and its Activity Log are saved (0600) and every 40-hex window of both is hashed: none matches.
    The positive control is that the printed hash is in the job's own log."""
    u, _, session = member
    repo = tracker.repo(u.name)
    full = repo["full_name"]
    branch, sha = _probe(repo, 'printf "H:%s\\n" "$(sha256sum < /run/ci/token | cut -d\' \' -f1)" ; sleep 60')
    paths: list[str] = []
    try:
        name = None

        def group_seen() -> bool:
            nonlocal name
            tracker.watch(repo["id"])
            name = _group_of(set(tracker.keys))
            return name is not None

        assert wait_for(group_seen, RUN_TIMEOUT, every=3), "no ACI group ever appeared for the probe"
        show = az("container", "show", "-g", CI_GROUP, "-n", name, "-o", "json")
        assert show.returncode == 0, "az container show failed"
        paths.append(_private_file("ci-group-", show.stdout))
        activity = az("monitor", "activity-log", "list", "-g", CI_GROUP, "--offset", "1h", "--query",
                      f"[?contains(resourceId,'{name}')]", "-o", "json", timeout=300)
        assert activity.returncode == 0, "az monitor activity-log list failed"
        paths.append(_private_file("ci-activity-", activity.stdout))
        assert _wait_success(tracker, repo, sha), "the probe did not reach success"
        printed = _hashes(job_log_text(session, full, sha))
        n_printed = len(printed)
        assert n_printed == 1, "positive control: the job's log must hold exactly one credential hash"
        candidates = set()
        for p in paths:
            with open(p) as f:
                text = f.read().lower()
            candidates |= {m.group(1) for m in re.finditer(r"(?=([0-9a-f]{40}))", text)}
        digests = {hashlib.sha256(c.encode()).hexdigest() for c in candidates}
        assert not (digests & printed), "the runner credential is in the group definition or its Activity Log"
    finally:
        for p in paths:
            os.unlink(p)
        delete_branch(full, branch)


SECRET_NAMES = ("CI_DISPATCH_FORGEJO_TOKEN", "CI_DISPATCH_USAGE_TOKEN", "CI_DISPATCH_AZURE_CLIENT_SECRET",
                "FORGEJO_ADMIN_TOKEN")


def test_dispatcher_secrets_not_in_group(member, tracker):  # F21
    """The job prints the sha256 of every token-shaped run (and of each run's text after a leading `NAME=`) in
    its environment and in each file under /run, /etc/ci-class and /root, so a secret inside a larger file is
    caught. The hashes are compared locally with the dispatcher's secrets: no match. A nonce planted inside a
    larger line of a file is the positive control."""
    u, _, session = member
    repo = tracker.repo(u.name)
    full = repo["full_name"]
    nonce = secrets.token_hex(16)                    # not a secret: it proves the search finds a value inside a file
    script = (HASH_TOKEN
              + f"printf 'planted note\\nexport ACC_KEY={nonce} # keep\\n' > /root/acc-planted.txt\n"
              + "{ env; tr '\\0' '\\n' < /proc/1/environ 2>/dev/null || true; } | sed 's/^[^=]*=//' | hash_runs\n"
              + "find /run /etc/ci-class /root -type f 2>/dev/null | while IFS= read -r f; do hash_runs < \"$f\"; done\n"
              + "sleep 5\n")
    branch, sha = _probe(repo, script)
    try:
        assert _wait_success(tracker, repo, sha), "the probe did not reach success"
        printed = _hashes(job_log_text(session, full, sha))
        n_printed = len(printed)
        assert n_printed >= 1, "the job printed no hashes, so the search proves nothing"
        assert hashlib.sha256(nonce.encode()).hexdigest() in printed, "positive control: the planted nonce was not found"
        env = {**_load_env(FORGE_SECRETS), **os.environ}
        values = [env[n] for n in SECRET_NAMES if len(env.get(n, "")) >= 16]
        n_secrets = len(values)                      # a count: pytest would print a list of secrets
        assert n_secrets >= 2, "too few of the dispatcher's secrets are available locally to search for"
        digests = {hashlib.sha256(v.encode()).hexdigest() for v in values}
        assert not (digests & printed), "a dispatcher or admin secret is inside the paid group"
    finally:
        delete_branch(full, branch)
