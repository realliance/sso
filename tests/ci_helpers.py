"""Helpers for the runner-class (ci-dispatch) acceptance tests. Secrets come from the unlocked
realliance/sso-secrets checkout and never reach argv or output."""
import atexit
import base64
import json
import os
import re
import secrets
import select
import subprocess
import threading
import time

import requests
import yaml

from conftest import _load_env
from forge_helpers import (FORGE, FORGE_SECRETS, KUBECONFIG, PROBE_WORKFLOW, forge_api, kube, runs_for,
                           wait_for)

CI_TOKEN_KEY = "CI_DISPATCH_FORGEJO_TOKEN"
# Local site administrators; the test adds the Owners at run time from the realliance-ops Owners team.
EXPECTED_ADMINS = {"forgejo-admin", "forge-bot", "ci-dispatch"}


def ci_token() -> str:
    """The ci-dispatch API token (KeyError if it is not minted yet). Never print it."""
    return _load_env(FORGE_SECRETS)[CI_TOKEN_KEY]


def forge_api_paged(path: str, limit: int = 50, **kw) -> list[dict]:
    """Every item of a paged Forgejo list endpoint, as the break-glass admin (50 is the page cap)."""
    items, page = [], 1
    while True:
        r = forge_api("GET", path, params={"page": page, "limit": limit}, **kw)
        r.raise_for_status()
        batch = r.json()
        items += batch
        if len(batch) < limit:
            return items
        page += 1


# --- runner proofs (runner classes plan Task 3, tests/forge/test_forge_runner_proofs.py) --------------
# The galaxy runner's image (forgejo-runner v13.2.1, node, uid 1000): cluster/forgejo-runner/deployment.yaml.
PROOF_IMAGE = ("ghcr.io/christopherjmiller/forgejo-runner:sha-6b269ab"
               "@sha256:3bb2fca689b0c986039be061a4201580488c30bcdcb476815f80d737f97b76e9")
PROBE_NS = "ci-probe"
DRILL_LABELS = {"app.kubernetes.io/part-of": "ci-probe-drill"}   # on every object the drill creates
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")                 # D18: what the dispatcher accepts
_TIMELINES: list[tuple[str, dict[str, float]]] = []


class Registration(dict):
    """A runner registration (`id`, `uuid`, `token`). repr and str never show the token, so neither
    pytest's assertion rewriting nor --showlocals can print it."""

    def __repr__(self) -> str:
        return f"Registration(id={self.get('id')!r}, uuid={self.get('uuid')!r}, token=<redacted>)"

    __str__ = __repr__


def push_workflow(repo: str, wf: dict, branch: str | None = None) -> tuple[str, str]:
    """push_probe_workflow's mechanics with a whole workflow (`jobs`, and `concurrency` if wanted).
    `name` (unique per commit) and `on` (push to ci-probe-*) are added unless `wf` sets them. Returns
    (branch, commit sha)."""
    wf = {"name": f"ci-probe {secrets.token_hex(3)}", "on": {"push": {"branches": ["ci-probe-*"]}}, **wf}
    body = {"content": base64.b64encode(yaml.safe_dump(wf, sort_keys=False).encode()).decode(),
            "message": "ci probe (realliance/sso tests)"}
    path = f"/api/v1/repos/{repo}/contents/{PROBE_WORKFLOW}"
    if branch is None:
        branch = f"ci-probe-{secrets.token_hex(4)}"
        r = forge_api("POST", path, json={**body, "new_branch": branch})
    else:
        cur = forge_api("GET", path, params={"ref": branch})
        cur.raise_for_status()
        r = forge_api("PUT", path, json={**body, "branch": branch, "sha": cur.json()["sha"]})
    r.raise_for_status()
    return branch, r.json()["commit"]["sha"]


def list_jobs(labels: list[str], token: str) -> list[dict]:
    """GET /admin/actions/runners/jobs: waiting and running jobs whose runs_on is a subset of `labels`
    (every waiting or running job when `labels` is empty)."""
    params = {"labels": ",".join(labels)} if labels else None
    r = forge_api("GET", "/api/v1/admin/actions/runners/jobs", token=token, params=params)
    r.raise_for_status()
    return r.json() or []            # Forgejo sends null, not [], when nothing matches


def register_ephemeral(name: str, token: str) -> Registration:
    """POST /admin/actions/runners with ephemeral: an instance-scope runner for one job. The result
    stays in memory: never log it, print it or put it in an assertion message."""
    r = forge_api("POST", "/api/v1/admin/actions/runners", token=token,
                  json={"name": name, "description": "ci-probe drill (realliance/sso tests)", "ephemeral": True})
    if r.status_code != 201:
        raise RuntimeError(f"runner registration refused: HTTP {r.status_code}")
    return Registration(r.json())


def runner_rows(token: str, *, visible: bool = False) -> list[dict]:
    """Every page of GET /admin/actions/runners. Forgejo 15 lists only instance-scope runners unless
    `visible` is set; with it, every runner on the forge."""
    items, page = [], 1
    while True:
        r = forge_api("GET", "/api/v1/admin/actions/runners", token=token,
                      params={"page": page, "limit": 50, "visible": str(visible).lower()})
        r.raise_for_status()
        batch = r.json() or []
        items += batch
        if len(batch) < 50:
            return items
        page += 1


def delete_runner(runner_id: int, token: str) -> int:
    """DELETE /admin/actions/runners/{id}; returns the status (204 deleted, 404 already gone)."""
    return forge_api("DELETE", f"/api/v1/admin/actions/runners/{runner_id}", token=token).status_code


def _pod_manifest(name: str, handle: str, reg: Registration, label: str, ns: str) -> dict:
    """The `tiny` pod shape (plan Global Constraints) around `forgejo-runner one-job`. The handle and
    uuid are argv elements; the shell only runs `mkdir` and passes "$@" through unparsed."""
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": ns, "labels": dict(DRILL_LABELS)},
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 1200,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "affinity": {"nodeAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [
                {"weight": 100, "preference": {"matchExpressions": [
                    {"key": "kubernetes.io/hostname", "operator": "NotIn", "values": ["top"]}]}}]}},
            "topologySpreadConstraints": [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname",
                                           "whenUnsatisfiable": "ScheduleAnyway",
                                           "labelSelector": {"matchLabels": dict(DRILL_LABELS)}}],
            "containers": [{
                "name": "runner",
                "image": PROOF_IMAGE,
                "command": ["sh", "-c", 'mkdir -p "$HOME" "$TMPDIR" && exec forgejo-runner "$@"', "forgejo-runner"],
                "args": ["one-job", "--wait", "--handle", handle, "--url", FORGE, "--uuid", reg["uuid"],
                         "--token-url", "file:///creds/token", "--label", f"{label}:host"],
                "env": [{"name": "HOME", "value": "/work/home"}, {"name": "TMPDIR", "value": "/work/tmp"}],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "runAsNonRoot": True, "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "1", "memory": "2Gi"}},
                "volumeMounts": [{"name": "work", "mountPath": "/work"},
                                 {"name": "creds", "mountPath": "/creds", "readOnly": True}],
            }],
            "volumes": [{"name": "work", "emptyDir": {"medium": "Memory", "sizeLimit": "1Gi"}},
                        {"name": "creds", "secret": {"secretName": name, "defaultMode": 0o440}}],
        },
    }


def probe_pod(name: str, handle: str, reg: Registration, label: str, *, ns: str = PROBE_NS) -> None:
    """Create Secret `name` (key `token`, the runner credential, sent to kubectl on stdin; `create`, not
    `apply`, so no last-applied annotation copies it) and Pod `name`, running
    `forgejo-runner one-job --wait --handle <handle> ... --label <label>:host` in the `tiny` shape. The
    credential reaches the pod only through that Secret's volume."""
    if not HANDLE_RE.match(handle):
        raise ValueError("handle is not of the form the dispatcher accepts (D18)")
    secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
              "metadata": {"name": name, "namespace": ns, "labels": dict(DRILL_LABELS)},
              "stringData": {"token": reg["token"]}}
    r = kube("create", "-f", "-", stdin=json.dumps(secret), timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"creating Secret {ns}/{name} failed (exit {r.returncode})")   # stderr withheld
    r = kube("create", "-f", "-", stdin=json.dumps(_pod_manifest(name, handle, reg, label, ns)), timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"creating Pod {ns}/{name} failed: {r.stderr.strip()[:300]}")


def pod_state(name: str, *, ns: str = PROBE_NS) -> dict | None:
    """The live Pod object, or None once it is gone."""
    r = kube("-n", ns, "get", "pod", name, "-o", "json", "--ignore-not-found", timeout=60)
    r.check_returncode()
    return json.loads(r.stdout) if r.stdout.strip() else None


def delete_probe(name: str, *, ns: str = PROBE_NS) -> None:
    """Delete the probe's Pod and Secret without waiting (best effort)."""
    kube("-n", ns, "delete", "pod,secret", name, "--ignore-not-found", "--wait=false", timeout=60)


def timeline(name: str = "") -> dict[str, float]:
    """A fresh {step: epoch seconds} dict, kept for the drill report. Steps: seen (job first in the
    listing), registered, pod_created, pod_running, job_running (task_id set), done."""
    tl: dict[str, float] = {}
    _TIMELINES.append((name or f"timeline-{len(_TIMELINES) + 1}", tl))
    return tl


def timelines() -> list[tuple[str, dict[str, float]]]:
    return list(_TIMELINES)


# --- leftover sweep (best-effort cleanup for the drill, tests/forge/test_forge_runner_proofs.py) ------
DRILL_RUNNER_DESCRIPTION = "ci-probe drill (realliance/sso tests)"      # register_ephemeral's
_DRILL_RUNNER = re.compile(r"^ci-probe-[0-9a-f]{8}-[a-z0-9]+$")          # f"{label}-{suffix}"
_DRILL_REPO = re.compile(r"^ci-probe-[0-9a-f]{8}$")                      # the drill's `_label()`
PROBE_REPO_OWNER = "forgejo-admin"


def sweep_leftovers(token: str, *, ns: str = PROBE_NS) -> dict:
    """Remove what an earlier drill run left behind, and only that: ephemeral instance runners whose name and
    description are the drill's, private forgejo-admin repos named ci-probe-<hex8>, and the pods and Secrets
    in `ns` that carry DRILL_LABELS (the runner token Secrets). Each step runs on its own: a failure is
    recorded in `errors` and the rest still run. Returns names and ids only."""
    out: dict = {"runners": [], "repos": [], "errors": []}

    def attempt(what: str, fn) -> None:
        try:
            fn()
        except Exception as e:                                            # noqa: BLE001 - best effort, reported
            out["errors"].append(f"{what}: {type(e).__name__}: {str(e)[:200]}")

    def pods_and_secrets() -> None:
        selector = ",".join(f"{k}={v}" for k, v in DRILL_LABELS.items())
        r = kube("-n", ns, "delete", "pod,secret", "-l", selector, "--ignore-not-found", "--wait=false", timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"kubectl delete exit {r.returncode}: {r.stderr.strip()[:150]}")

    def runners() -> None:
        for row in runner_rows(token, visible=True):
            if (row.get("ephemeral") and row.get("description") == DRILL_RUNNER_DESCRIPTION
                    and _DRILL_RUNNER.match(row["name"])):
                attempt(f"delete runner {row['id']}", lambda row=row: _delete_runner_ok(row["id"], token))
                out["runners"].append(row["id"])

    def repos() -> None:
        for repo in forge_api_paged(f"/api/v1/users/{PROBE_REPO_OWNER}/repos"):
            if repo["private"] and _DRILL_REPO.match(repo["name"]):
                attempt(f"delete repo {repo['name']}", lambda repo=repo: _delete_repo_ok(repo["full_name"]))
                out["repos"].append(repo["name"])

    attempt("pods and secrets", pods_and_secrets)
    attempt("runners", runners)
    attempt("repos", repos)
    return out


def _delete_runner_ok(runner_id: int, token: str) -> None:
    status = delete_runner(runner_id, token)
    if status not in (204, 404):
        raise RuntimeError(f"HTTP {status}")


def _delete_repo_ok(full_name: str) -> None:
    status = forge_api("DELETE", f"/api/v1/repos/{full_name}").status_code
    if status not in (204, 404):
        raise RuntimeError(f"HTTP {status}")


# --- ci-dispatch / `tiny` acceptance (runner classes plan Task 16, tests/forge/test_forge_ci_tiny.py) -----
DISPATCH_NS = "ci-dispatch"
TINY_NS = "ci-tiny"
USAGE_TOKEN_KEY = "CI_DISPATCH_USAGE_TOKEN"
RUN_DONE = {"success", "failure", "cancelled", "skipped"}
_FORWARD: dict = {}


def usage_token() -> str:
    """The usage API's bearer token (KeyError if it is not minted yet). Never print it."""
    return _load_env(FORGE_SECRETS)[USAGE_TOKEN_KEY]


def _stop_forward() -> None:
    proc = _FORWARD.pop("proc", None)
    _FORWARD.pop("port", None)
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


atexit.register(_stop_forward)


def _forward_port() -> int:
    """Local port of a `kubectl port-forward svc/ci-dispatch 0:8081` (D15: the usage API has no ingress,
    so kubectl, which enters the pod over localhost, is the way in). Started once, restarted if it died."""
    proc = _FORWARD.get("proc")
    if proc is not None and proc.poll() is None:
        return _FORWARD["port"]
    _stop_forward()
    proc = subprocess.Popen(["kubectl", "-n", DISPATCH_NS, "port-forward", "svc/ci-dispatch", "0:8081"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            env={**os.environ, "KUBECONFIG": KUBECONFIG})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 1)
        if ready:
            m = re.match(r"Forwarding from 127\.0\.0\.1:(\d+) ", proc.stdout.readline())
            if m:
                _FORWARD.update(proc=proc, port=int(m.group(1)))
                # kubectl logs "Handling connection" per request: drain it so the pipe never fills and stalls.
                threading.Thread(target=lambda: [None for _ in proc.stdout], daemon=True).start()
                return _FORWARD["port"]
        if proc.poll() is not None:
            break
    proc.kill()
    raise RuntimeError("kubectl port-forward to svc/ci-dispatch:8081 did not come up")


def usage_raw(owner_id: int, token: str | None = None, *, period: str = "current",
              what: str = "usage") -> requests.Response:
    """GET /v1/owners/{owner_id}/{what}?period=… on the usage API, with `Authorization: Bearer <token>`
    when a token is given (header only, never argv or URL), unauthenticated when it is None."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    last: Exception | None = None
    for _ in range(2):
        try:
            return requests.get(f"http://127.0.0.1:{_forward_port()}/v1/owners/{owner_id}/{what}",
                                params={"period": period}, headers=headers, timeout=15)
        except requests.ConnectionError as e:        # the forward died between calls: restart it once
            last = e
            _stop_forward()
    raise RuntimeError(f"usage API unreachable: {type(last).__name__}")


def usage(owner_id: int, *, period: str = "current") -> dict:
    """The owner's usage document (spec "Usage API"), read with the usage token."""
    tok = usage_token()
    r = usage_raw(owner_id, tok, period=period)
    if r.status_code != 200:
        raise RuntimeError(f"usage API answered HTTP {r.status_code} for owner {owner_id}")
    return r.json()


def kube_bytes(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    """`kubectl <args>` against galaxy with the output kept as bytes (exec output can be binary)."""
    return subprocess.run(["kubectl", *args], capture_output=True, timeout=timeout,
                          env={**os.environ, "KUBECONFIG": KUBECONFIG})


def tiny_objects(kinds: str = "job,pod,secret") -> list[dict]:
    """Every object of `kinds` in ci-tiny (RuntimeError if kubectl fails: an unreadable namespace is not
    an empty one)."""
    r = kube("-n", TINY_NS, "get", kinds, "-o", "json", timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"kubectl get {kinds} in {TINY_NS} failed (exit {r.returncode})")
    return json.loads(r.stdout)["items"]


def job_key(job: dict) -> str:
    """The dispatcher's key for a job-listing row: `<job id>-<attempt>` (label `ci-dispatch/key`)."""
    return f"{job['id']}-{job.get('attempt', 1)}"


def tiny_pods(key: str | None = None) -> list[dict]:
    """The Pods in ci-tiny, or those of one key."""
    pods = tiny_objects("pod")
    return [p for p in pods if key is None or p["metadata"].get("labels", {}).get("ci-dispatch/key") == key]


def tiny_leftovers(keys: set[str]) -> list[str]:
    """Kind/name of every Job, Pod or Secret in ci-tiny that belongs to one of `keys`, by the key label or
    by the `<job>-<attempt>` in its name, plus every runner `ci-tiny-<job>-<attempt>-*` on the forge."""
    out = []
    for o in tiny_objects():
        name = o["metadata"]["name"]
        if (o["metadata"].get("labels", {}).get("ci-dispatch/key") in keys
                or any(f"ci-tiny-{k}-" in name or name == f"ci-tiny-{k}" for k in keys)):
            out.append(f"{o['kind']}/{name}")
    tok = ci_token()
    for row in runner_rows(tok, visible=True):
        if any(row["name"].startswith(f"ci-tiny-{k}-") for k in keys):
            out.append(f"runner/{row['name']}")
    return out


def run_status(repo: str, sha: str) -> str | None:
    """Status of the (first) Actions run for commit `sha`, or None while no run exists yet."""
    runs = runs_for(repo, sha)
    return runs[0]["status"] if runs else None


def wait_status(repo: str, sha: str, status: str, timeout: float = 300, every: float = 5) -> bool:
    """True once the run for `sha` has `status` (waiting, running, success, failure, cancelled …); False at
    `timeout`, or as soon as the run is done in some other status (it can't change any more)."""
    done_wrong = []

    def pred() -> bool:
        s = run_status(repo, sha)
        if s in RUN_DONE and s != status:
            done_wrong.append(s)
        return s == status or bool(done_wrong)

    wait_for(pred, timeout, every)
    return not done_wrong and run_status(repo, sha) == status
