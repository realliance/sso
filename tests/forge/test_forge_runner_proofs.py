"""Phase 0 proofs for the runner classes (luma-homeops plan 2026-11-04-runner-classes-phase-0-1, Task 3;
D14): the Forgejo path the ci-dispatch design rests on, proved on the live forge and galaxy. An
instance-scope ephemeral runner registered through the API, `forgejo-runner one-job --wait --handle <h>`
in a throwaway pod, the runner row gone afterwards, the spent credential refused, and the start latency.

A drill, not part of the suite: every test is slow and skips unless CI_DRILL=runner-proofs. Re-run it at
the Forgejo 17 and 19 LTS upgrades, because everything rests on the `--handle` semantics:

    CI_DRILL=runner-proofs CI_DRILL_REPORT=<scratch>/runner-proofs.json \\
        nix develop --command pytest tests/forge/test_forge_runner_proofs.py -v

Before: create namespace ci-probe (Pod Security `restricted`, no NetworkPolicy). After: delete it.
The drill creates the private repo forgejo-admin/ci-probe-<hex> and deletes it, with every runner, pod
and Secret it made. Each scenario uses a fresh label ci-probe-<hex> that no other runner carries, so a
mistake cannot take another repo's job; the probe workflows run only `run:` steps, so no action is
downloaded. Runner credentials stay in this process and reach a pod only through a Secret's volume.
"""
import json
import os
import secrets
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime

import pytest

from ci_helpers import (PROBE_NS, Registration, ci_token, delete_probe, delete_runner, list_jobs, pod_state,
                        probe_pod, push_workflow, register_ephemeral, runner_rows, timeline, timelines)
from forge_helpers import forge_api, kube

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.environ.get("CI_DRILL") != "runner-proofs",
                                 reason="runner-proofs drill: set CI_DRILL=runner-proofs")]

DONE = {"success", "failure", "cancelled", "skipped"}

# Job A's script: the tiny pod shape as the job sees it. uid/gid 1000, /work a tmpfs, HOME and TMPDIR
# under /work and writable, the root filesystem read-only, no service-account token. The sleep keeps the
# job running long enough for the 2 s row poll to see it.
SHAPE_SCRIPT = """\
set -eu
test "$(id -u)" = 1000
test "$(id -g)" = 1000
grep -q '^[^ ]* /work tmpfs ' /proc/mounts
case "${HOME:-}" in /work/*) ;; *) echo "HOME is not under /work" >&2; exit 1;; esac
case "${TMPDIR:-}" in /work/*) ;; *) echo "TMPDIR is not under /work" >&2; exit 1;; esac
touch "$HOME/.ci-probe" "$TMPDIR/.ci-probe"
if touch /.ci-probe-ro 2>/dev/null; then echo "the root filesystem is writable" >&2; exit 1; fi
test ! -e /var/run/secrets/kubernetes.io
sleep 10
"""


@dataclass
class Drill:
    repo: str
    repo_id: int
    token: str = field(repr=False)                       # ci-dispatch's; never printed
    runners: list[int] = field(default_factory=list)     # every runner id the drill registered
    pods: list[str] = field(default_factory=list)
    records: dict = field(default_factory=dict)          # the report: statuses, timings, answers


def _label() -> str:
    return f"ci-probe-{secrets.token_hex(4)}"


def _jobs(d: Drill, labels: list[str]) -> dict[str, dict]:
    """The probe repo's jobs in the listing, by job name (names are unique across the drill)."""
    return {j["name"]: j for j in list_jobs(labels, d.token) if j["repo_id"] == d.repo_id}


def _tasks(d: Drill, sha: str) -> dict[str, dict]:
    """The commit's tasks (one per picked-up job attempt), by job name."""
    r = forge_api("GET", f"/api/v1/repos/{d.repo}/actions/tasks", params={"limit": 50})
    r.raise_for_status()
    return {t["name"]: t for t in r.json()["workflow_runs"] if t["head_sha"] == sha}


def _row(d: Drill, runner_id: int) -> dict | None:
    return next((r for r in runner_rows(d.token) if r["id"] == runner_id), None)


def _until(fn, timeout: float, every: float = 1.0):
    """fn()'s first truthy result, or None after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.monotonic() > deadline:
            return None
        time.sleep(every)


def _seen(d: Drill, labels: list[str], names: set[str], tl: dict, timeout: float = 120) -> dict[str, dict]:
    jobs = _until(lambda: (j if names <= (j := _jobs(d, labels)).keys() else None), timeout)
    assert jobs, f"jobs {sorted(names)} never appeared in the listing"
    tl["seen"] = time.time()
    return jobs


def _register(d: Drill, name: str, tl: dict) -> Registration:
    reg = register_ephemeral(name, d.token)
    tl["registered"] = time.time()
    d.runners.append(reg["id"])
    return reg


def _launch(d: Drill, name: str, handle: str, reg: Registration, label: str, tl: dict) -> None:
    probe_pod(name, handle, reg, label)
    tl["pod_created"] = time.time()
    d.pods.append(name)


def _phase(pod: dict | None) -> str | None:
    return pod["status"].get("phase") if pod else None


def _terminated(pod: dict | None) -> dict | None:
    for cs in (pod or {}).get("status", {}).get("containerStatuses", []):
        if "terminated" in cs.get("state", {}):
            return cs["state"]["terminated"]
    return None


def _pod_facts(name: str, wait: float = 60) -> dict:
    """Where the pod ran, how it ended and what the kubelet said about its image (no secret is in any of
    them). Waits up to `wait` s for the pod to finish first."""
    pod = _until(lambda: (p if _phase(p := pod_state(name)) in ("Succeeded", "Failed") else None), wait, every=1)
    pod = pod or pod_state(name)
    ev = kube("-n", PROBE_NS, "get", "events", "--field-selector", f"involvedObject.name={name}",
              "-o", "json", timeout=60)
    msgs = [e["message"] for e in json.loads(ev.stdout).get("items", [])
            if e.get("reason") in ("Pulled", "Pulling")] if ev.returncode == 0 else []
    return {"node": (pod or {}).get("spec", {}).get("nodeName"), "image": msgs, "terminated": _terminated(pod)}


def _logs(name: str) -> str:
    r = kube("-n", PROBE_NS, "logs", name, "-c", "runner", timeout=60)
    return r.stdout if r.returncode == 0 else ""


def _follow(d: Drill, *, pod: str, job: str, sha: str, tl: dict, labels: list[str],
            runner_id: int | None = None, after: float = 0, every: float = 2.0, timeout: float = 900) -> list[dict]:
    """Sample every `every` s until the job is done and `after` more seconds have passed: the pod's
    phase, the probe repo's jobs in the listing, the job's task and (with runner_id) the runner row.
    Fills tl's pod_running, job_running and done the first time each is seen."""
    samples, deadline = [], time.monotonic() + timeout
    while time.monotonic() < deadline:
        now = time.time()
        p = pod_state(pod)
        jobs = _jobs(d, labels)
        task = _tasks(d, sha).get(job)
        s = {"t": now, "pod": _phase(p), "task": task and task["status"],
             "jobs": {n: (j["status"], j["task_id"]) for n, j in jobs.items()}}
        if runner_id is not None:
            row = _row(d, runner_id)
            s["row"] = row and {k: row[k] for k in ("status", "labels", "version", "ephemeral", "owner_id", "repo_id")}
        samples.append(s)
        picked = bool(task or (job in jobs and jobs[job]["task_id"]))
        if s["pod"] in ("Running", "Succeeded", "Failed") or picked:     # the kubelet can lag the job
            tl.setdefault("pod_running", now)
        if picked:
            tl.setdefault("job_running", now)
        if task and task["status"] in DONE:
            tl.setdefault("done", now)
        if "done" in tl and now - tl["done"] >= after:
            return samples
        time.sleep(every)
    return samples


@pytest.fixture(scope="module")
def drill():
    token = ci_token()
    ns = kube("get", "namespace", PROBE_NS, "-o", "json", timeout=60)
    if ns.returncode != 0:
        pytest.fail(f"namespace {PROBE_NS} is missing: create it first (Pod Security restricted)")
    if json.loads(ns.stdout)["metadata"].get("labels", {}).get("pod-security.kubernetes.io/enforce") != "restricted":
        pytest.fail(f"namespace {PROBE_NS} does not enforce Pod Security restricted")
    name = _label()
    r = forge_api("POST", "/api/v1/user/repos", json={"name": name, "private": True, "auto_init": True,
                                                      "default_branch": "main"})
    if r.status_code != 201:
        pytest.fail(f"creating the probe repo failed: HTTP {r.status_code}")
    d = Drill(repo=f"forgejo-admin/{name}", repo_id=r.json()["id"], token=token)
    d.records["forgejo"] = forge_api("GET", "/api/v1/version").json().get("version")
    try:
        r = forge_api("PATCH", f"/api/v1/repos/{d.repo}", json={"has_actions": True})
        r.raise_for_status()
        yield d
    finally:
        kube("-n", PROBE_NS, "delete", "pod,secret", "-l", "app.kubernetes.io/part-of=ci-probe-drill",
             "--ignore-not-found", "--wait=false", timeout=120)
        d.records["runner_deletes"] = {rid: delete_runner(rid, token) for rid in d.runners}   # 404 = already gone
        d.records["leftover_runners"] = sorted(r["name"] for r in runner_rows(token, visible=True)
                                               if r["name"].startswith("ci-probe-"))
        forge_api("DELETE", f"/api/v1/repos/{d.repo}")
        d.records["repo_after_delete"] = forge_api("GET", f"/api/v1/repos/{d.repo}").status_code
        d.records["jobs_left_in_repo"] = [j["id"] for j in list_jobs([], token) if j["repo_id"] == d.repo_id]
        _report(d)


def _report(d: Drill) -> None:
    """Write the drill's records and timelines to CI_DRILL_REPORT (JSON) when it is set. Ids, statuses
    and timings only."""
    tls = [{"name": n, **tl} for n, tl in timelines()]
    lat = [tl["job_running"] - tl["registered"] for n, tl in timelines()
           if "registered" in tl and "job_running" in tl and tl.get("latency_sample")]
    d.records["latency_registered_to_running_s"] = {
        "samples": [round(x, 1) for x in lat],
        "median": round(statistics.median(lat), 1) if lat else None,
        "max": round(max(lat), 1) if lat else None}
    out = os.environ.get("CI_DRILL_REPORT")
    if out:
        with open(out, "w") as f:
            json.dump({"records": d.records, "timelines": tls}, f, indent=1, default=str)


# --- A and B: one runner, A's handle --------------------------------------------------------------------
@dataclass
class HandleRun:
    label: str
    a: dict
    b: dict
    reg: Registration = field(repr=False)
    tl: dict
    samples: list[dict]
    pod: dict
    final_jobs: dict[str, dict]


@pytest.fixture(scope="module")
def handle_run(drill) -> HandleRun:
    """Two waiting jobs, a and b, on one fresh label; one ephemeral runner; a pod with a's handle. Followed
    every 2 s until 60 s after a ends."""
    d, label = drill, _label()
    tl = timeline("handle: job a")
    tl["latency_sample"] = 1.0
    _, sha = push_workflow(d.repo, {"jobs": {
        "a": {"runs-on": label, "steps": [{"run": SHAPE_SCRIPT}]},
        "b": {"runs-on": label, "steps": [{"run": "true"}]}}})
    tl["pushed"] = time.time()
    jobs = _seen(d, [label], {"a", "b"}, tl)
    reg = _register(d, f"{label}-a", tl)
    row0 = _row(d, reg["id"])
    _launch(d, f"{label}-a", jobs["a"]["handle"], reg, label, tl)
    samples = _follow(d, pod=f"{label}-a", job="a", sha=sha, tl=tl, labels=[label], runner_id=reg["id"], after=60)
    pod = pod_state(f"{label}-a") or {}
    facts = _pod_facts(f"{label}-a")
    final = _tasks(d, sha)
    d.records["handle"] = {
        "jobs_seen": {n: {k: j[k] for k in ("id", "attempt", "status", "task_id", "runs_on", "needs")}
                      for n, j in jobs.items()},
        "row_at_registration": row0 and {k: row0[k] for k in ("status", "labels", "version", "ephemeral",
                                                              "owner_id", "repo_id")},
        "tasks": {n: t["status"] for n, t in final.items()}, "pod": facts,
        "row_samples": [(round(s["t"] - tl["registered"], 1), s.get("row") and s["row"]["status"], s["task"])
                        for s in samples]}
    delete_probe(f"{label}-a")
    return HandleRun(label=label, a=jobs["a"], b=jobs["b"], reg=reg, tl=tl, samples=samples, pod=pod,
                     final_jobs=final)


def test_handle_binds_runner_to_one_attempt(handle_run):
    h = handle_run
    assert "done" in h.tl, "job a never finished"
    assert h.final_jobs["a"]["status"] == "success"
    assert "b" not in h.final_jobs                        # b was never picked up ...
    last = h.samples[-1]
    assert last["t"] - h.tl["done"] >= 60
    assert last["jobs"].get("b") == ("waiting", 0)        # ... and still waits 60 s after a ended
    assert all(s["jobs"].get("b") == ("waiting", 0) for s in h.samples)


def test_runner_row_lifecycle(drill, handle_run):
    h = handle_run
    rows = [(s["t"], s.get("row")) for s in h.samples]
    assert rows and rows[0][1] is not None, "the runner row was not there after registration"
    running = [r for t, r in rows if h.tl.get("job_running", 1e18) <= t < h.tl.get("done", 0)]
    gone = next((t for t, r in rows if r is None), None)
    rec = drill.records["row_lifecycle"] = {
        "while_waiting": sorted({r["status"] for t, r in rows if r and t < h.tl.get("job_running", 1e18)}),
        "while_running": sorted({r["status"] for r in running if r}),
        "row_present_while_running": bool(running) and all(r is not None for r in running),
        "gone_after_done_s": None if gone is None else round(gone - h.tl["done"], 1),
        "labels_after_declare": next((r["labels"] for t, r in rows if r and r["labels"]), None),
        "ephemeral": rows[0][1]["ephemeral"], "scope": (rows[0][1]["owner_id"], rows[0][1]["repo_id"])}
    assert gone is not None, f"the runner row never disappeared ({rec})"
    assert gone - h.tl["done"] <= 60


def test_spent_credential_rejected(drill, handle_run):
    """A second pod with a's uuid and token, after a's job ended, asking for b's handle."""
    d, h = drill, handle_run
    tl = timeline("spent credential")
    name = f"{h.label}-spent"
    _launch(d, name, h.b["handle"], h.reg, h.label, tl)
    pod = _until(lambda: (p if _phase(p := pod_state(name)) in ("Succeeded", "Failed") else None), 300, every=2)
    tl["pod_done"] = time.time()
    term = _terminated(pod) or {}
    logs = _logs(name)
    lines = [ln[:200] for ln in logs.splitlines() if "unauthenticated" in ln.lower() or "declare" in ln.lower()]
    jobs = _jobs(d, [h.label])
    started, finished = term.get("startedAt"), term.get("finishedAt")
    secs = None
    if started and finished:
        secs = (datetime.fromisoformat(finished.replace("Z", "+00:00"))
                - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds()
    d.records["spent"] = {"exit": term.get("exitCode"), "ran_s": secs, "log": lines[:5],
                          "b_after": jobs.get("b") and (jobs["b"]["status"], jobs["b"]["task_id"]),
                          "pod": _pod_facts(name)}
    delete_probe(name)
    assert pod is not None, "the spent-credential pod never finished"
    assert term.get("exitCode") not in (None, 0)
    assert secs is not None and secs <= 60
    assert any("unauthenticated" in ln.lower() for ln in lines), "no authentication error in the runner log"
    assert jobs.get("b") and (jobs["b"]["status"], jobs["b"]["task_id"]) == ("waiting", 0)


def test_pod_shape_runs(handle_run):
    """A's pod had the tiny shape, and A's job (SHAPE_SCRIPT) saw it from inside: uid 1000, /work tmpfs,
    HOME and TMPDIR under /work, read-only root, no service-account token."""
    spec = handle_run.pod["spec"]
    c = spec["containers"][0]
    sc, psc = c["securityContext"], spec["securityContext"]
    assert (psc["runAsUser"], psc["runAsGroup"], psc["runAsNonRoot"]) == (1000, 1000, True)
    assert psc["seccompProfile"]["type"] == "RuntimeDefault"
    assert sc["readOnlyRootFilesystem"] is True and sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"] == {"drop": ["ALL"]}
    assert spec["automountServiceAccountToken"] is False and spec["enableServiceLinks"] is False
    work = next(v for v in spec["volumes"] if v["name"] == "work")
    assert work["emptyDir"] == {"medium": "Memory", "sizeLimit": "1Gi"}
    env = {e["name"]: e["value"] for e in c["env"]}
    assert (env["HOME"], env["TMPDIR"]) == ("/work/home", "/work/tmp")
    assert c["resources"] == {"requests": {"cpu": "250m", "memory": "512Mi"}, "limits": {"cpu": "1", "memory": "2Gi"}}
    assert handle_run.final_jobs["a"]["status"] == "success"     # the in-job checks passed


# --- the listing -----------------------------------------------------------------------------------------
def test_labels_subset_rule(drill):
    d, label = drill, _label()
    tl = timeline("labels")
    push_workflow(d.repo, {"jobs": {
        "l1": {"runs-on": [label], "steps": [{"run": "true"}]},
        "l2": {"runs-on": [label, "docker"], "steps": [{"run": "true"}]},
        "l3": {"runs-on": ["docker"], "steps": [{"run": "true"}]},
        "l4": {"runs-on": [label, "other"], "steps": [{"run": "true"}]}}})
    _seen(d, [], {"l1", "l2", "l3", "l4"}, tl)
    with_docker = {n for n in _jobs(d, [label, "docker"]) if n.startswith("l")}
    only_label = {n for n in _jobs(d, [label]) if n.startswith("l")}
    d.records["labels"] = {"labels=L,docker": sorted(with_docker), "labels=L": sorted(only_label)}
    assert with_docker == {"l1", "l2", "l3"}
    assert only_label == {"l1"}


def test_needs_and_concurrency_visibility(drill):
    """b needs a; c2 queues behind c1 in one concurrency group (cancel-in-progress: false). The dispatcher
    launches only for status == "waiting", so a job held back must never show as waiting. A runner with c2's
    handle proves the hold is real; then c1 runs and c2 follows."""
    d, label = drill, _label()
    group = f"ci-probe-{secrets.token_hex(4)}"
    tl = timeline("needs and concurrency")
    push_workflow(d.repo, {"jobs": {
        "na": {"runs-on": label, "steps": [{"run": "true"}]},
        "nb": {"runs-on": label, "needs": "na", "steps": [{"run": "true"}]}}})
    conc = {"group": group, "cancel-in-progress": False}
    _, sha1 = push_workflow(d.repo, {"concurrency": conc, "jobs": {"c1": {"runs-on": label, "steps": [{"run": "true"}]}}})
    _seen(d, [label], {"na", "c1"}, tl)
    _, sha2 = push_workflow(d.repo, {"concurrency": conc, "jobs": {"c2": {"runs-on": label, "steps": [{"run": "true"}]}}})
    jobs = _seen(d, [label], {"na", "c1", "c2"}, tl)
    time.sleep(10)                                        # nb has had time to show, if it ever would
    jobs = _jobs(d, [label])
    every = _jobs(d, [])                                  # any label at all
    shown = {n: {"status": j["status"], "needs": j["needs"], "task_id": j["task_id"]} for n, j in every.items()
             if n in ("na", "nb", "c1", "c2")}
    rec = d.records["needs_concurrency"] = {"listing": shown}

    # Is c2 really held? A runner bound to c2's handle, polling, must not get it while c1 waits.
    tl_h = timeline("concurrency c2 (held)")
    reg_h = _register(d, f"{label}-c2", tl_h)
    _launch(d, f"{label}-c2", jobs["c2"]["handle"], reg_h, label, tl_h)
    declared = _until(lambda: (r if (r := _row(d, reg_h["id"])) and r["labels"] else None), 300, every=2)
    tl_h["declared"] = tl_h["pod_running"] = time.time()  # a runner that declared is running
    held, rows_h = [], []
    for _ in range(23):                                   # ~45 s
        j = _jobs(d, [label]).get("c2")
        held.append(j and (j["status"], j["task_id"]))
        rows_h.append((r := _row(d, reg_h["id"])) and r["status"])
        time.sleep(2)
    c2_held = bool(declared) and all(x == ("waiting", 0) for x in held)
    rec["c2_held_while_c1_waits"] = c2_held
    rec["c2_samples_while_held"] = sorted({str(x) for x in held})
    rec["held_runner_row_status"] = sorted({str(x) for x in rows_h})

    # Release: c1 runs, and c2's runner then gets c2.
    tl_1 = timeline("concurrency c1")
    tl_1["latency_sample"] = 1.0
    tl_1["seen"] = tl["seen"]
    reg_1 = _register(d, f"{label}-c1", tl_1)
    _launch(d, f"{label}-c1", jobs["c1"]["handle"], reg_1, label, tl_1)
    _follow(d, pod=f"{label}-c1", job="c1", sha=sha1, tl=tl_1, labels=[label], every=1)
    _follow(d, pod=f"{label}-c2", job="c2", sha=sha2, tl=tl_h, labels=[label], every=1, timeout=300)
    t1, t2 = _tasks(d, sha1).get("c1"), _tasks(d, sha2).get("c2")
    rec["after_release"] = {"c1": t1 and t1["status"], "c2": t2 and t2["status"],
                            "c2_running_after_c1_done_s": round(tl_h["job_running"] - tl_1["done"], 1)
                            if "job_running" in tl_h and "done" in tl_1 else None}
    rec["pods"] = {"c1": _pod_facts(f"{label}-c1"), "c2": _pod_facts(f"{label}-c2")}
    delete_probe(f"{label}-c1")
    delete_probe(f"{label}-c2")

    assert shown.get("na", {}).get("status") == "waiting"
    assert c2_held, "c2 was not held behind c1, so the concurrency half proves nothing"
    held_back = ["nb", "c2"]
    as_waiting = [n for n in held_back if shown.get(n, {}).get("status") == "waiting"]
    rec["held_back_shown_as_waiting"] = as_waiting
    assert not as_waiting, f"held-back jobs listed as waiting: {as_waiting} (STOP: Task 11 needs another signal)"


def test_repo_listing_scope(drill):
    """F15: does a repo's runner listing include an instance-scope ephemeral runner? Asked of the probe
    repo and of realliance/forge-bot, the call tests/forge/test_forge_ci.py makes."""
    d, label = drill, _label()
    tl = timeline("repo listing scope")
    reg = _register(d, f"{label}-scope", tl)

    def names(repo: str, **params) -> set[str]:
        r = forge_api("GET", f"/api/v1/repos/{repo}/actions/runners", params=params or None)
        r.raise_for_status()
        return {x["name"] for x in r.json() or []}

    mine = f"{label}-scope"
    ans = {"probe repo, default": mine in names(d.repo), "probe repo, visible=true": mine in names(d.repo, visible="true"),
           "forge-bot, default": mine in names("realliance/forge-bot"),
           "forge-bot, visible=true": mine in names("realliance/forge-bot", visible="true"),
           "admin, default": any(r["id"] == reg["id"] for r in runner_rows(d.token))}
    status = delete_runner(reg["id"], d.token)
    ans["delete"] = status
    ans["admin, after delete"] = any(r["id"] == reg["id"] for r in runner_rows(d.token))
    d.records["repo_listing_scope"] = ans
    assert ans["probe repo, visible=true"] and ans["admin, default"]      # it exists and is visible ...
    assert status == 204 and not ans["admin, after delete"]               # ... and DELETE removes it


# --- start latency ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("n", [1, 2, 3])
def test_start_latency(drill, n):
    """Three more one-job runs, one after another, for the registration-to-running numbers."""
    d, label = drill, _label()
    tl = timeline(f"latency {n}")
    tl["latency_sample"] = 1.0
    job = f"t{n}"
    _, sha = push_workflow(d.repo, {"jobs": {job: {"runs-on": label, "steps": [{"run": "true"}]}}})
    jobs = _seen(d, [label], {job}, tl)
    reg = _register(d, f"{label}-{job}", tl)
    _launch(d, f"{label}-{job}", jobs[job]["handle"], reg, label, tl)
    _follow(d, pod=f"{label}-{job}", job=job, sha=sha, tl=tl, labels=[label], every=1, timeout=600)
    d.records.setdefault("latency_pods", {})[job] = _pod_facts(f"{label}-{job}")
    delete_probe(f"{label}-{job}")
    assert "job_running" in tl and "done" in tl
    assert _tasks(d, sha)[job]["status"] == "success"
