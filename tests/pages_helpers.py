"""Helpers for the Realliance Pages acceptance suite (tests/forge/test_forge_pages.py): static sites at
<owner>.realliance.page, served by git-pages and fed by the pages-relay webhook relay on galaxy.
Shared forge helpers are used as they are (forge_helpers.py is not edited); anything extra lives here.
The webhook secret comes from the unlocked sso-secrets checkout and never reaches argv or output."""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import select
import shlex
import stat
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

from conftest import _load_env
from forge_helpers import FORGE, FORGE_SECRETS, VPS, forge_api, kube

DOMAIN = "realliance.page"
RELAY_URL = "http://pages-relay.pages.svc.cluster.local:8080/hook"
GIT_PAGES_CONFIG = "/etc/git-pages/config.toml"
HOOK_EVENTS = ["push", "delete", "repository"]


def site_url(owner: str, repo: str) -> str:
    """Where the repo's site is served. Names are lower-cased; `<owner>/pages` is the owner's root site."""
    owner, repo = owner.lower(), repo.lower()
    return f"https://{owner}.{DOMAIN}/" if repo == "pages" else f"https://{owner}.{DOMAIN}/{repo}/"


def site_name(owner: str, repo: str) -> str:
    """The git-pages admin-CLI name of that site: `<domain>` for the root site, else `<domain>/<project>`."""
    owner, repo = owner.lower(), repo.lower()
    return f"{owner}.{DOMAIN}" if repo == "pages" else f"{owner}.{DOMAIN}/{repo}"


# --- the secret (created by Task 5; until then everything that needs it fails here, loudly) -----------------
def webhook_secret() -> str:
    """PAGES_WEBHOOK_SECRET from sso-secrets forge/secrets.env. Task 5 creates it: before that, the tests
    that sign requests fail with this message. The value is never printed."""
    value = _load_env(FORGE_SECRETS).get("PAGES_WEBHOOK_SECRET")
    if not value:
        pytest.fail("PAGES_WEBHOOK_SECRET is not in sso-secrets forge/secrets.env yet (Task 5 creates it)",
                    pytrace=False)
    return value


# --- forge repos and commits ----------------------------------------------------------------------------
def make_repo(owner: str, name: str, *, private: bool) -> None:
    """Create `owner/name` as that user. The forge defaults to private, so `private` is always explicit."""
    r = forge_api("POST", "/api/v1/user/repos", sudo=owner,
                  json={"name": name, "private": private, "auto_init": True})
    assert r.status_code == 201, f"creating {owner}/{name} gave {r.status_code}"


def commit_files(owner: str, repo: str, files: dict[str, str | bytes], *, branch: str = "pages") -> str:
    """Commit `files` to `branch` through the contents API, creating the branch off the default branch if
    it does not exist yet. Existing paths are updated, new ones created. Returns the commit sha."""
    base = f"/api/v1/repos/{owner}/{repo}"
    exists = forge_api("GET", f"{base}/branches/{branch}").status_code == 200
    ops = []
    for path, content in files.items():
        data = content.encode() if isinstance(content, str) else content
        op = {"operation": "create", "path": path, "content": base64.b64encode(data).decode()}
        if exists:
            cur = forge_api("GET", f"{base}/contents/{path}", params={"ref": branch})
            if cur.status_code == 200:
                op.update(operation="update", sha=cur.json()["sha"])
        ops.append(op)
    body = {"message": "pages acceptance test", "files": ops}
    if exists:
        body["branch"] = branch
    else:
        body["new_branch"] = branch
    r = forge_api("POST", f"{base}/contents", json=body)
    assert r.status_code in (200, 201), f"commit to {owner}/{repo}@{branch} gave {r.status_code}"
    return r.json()["commit"]["sha"]


def git_env(tmp: Path, user: str, token: str) -> dict:
    """The environment for a git subprocess against the forge: credentials travel in env via an askpass
    script, never argv, and no user or system git config applies."""
    askpass = tmp / "askpass.sh"
    askpass.write_text('#!/bin/sh\ncase "$1" in Username*) echo "$FORGE_USER";; *) echo "$FORGE_TOKEN";; esac\n')
    askpass.chmod(stat.S_IRWXU)
    return dict(os.environ, GIT_ASKPASS=str(askpass), FORGE_USER=user, FORGE_TOKEN=token,
                GIT_TERMINAL_PROMPT="0", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def git(cwd: Path, *args: str, env: dict) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"git {args[0]} failed: {r.stderr[-300:]}"
    return r.stdout


def push_payload(owner: str, repo: str, *, ref: str = "refs/heads/pages", after: str | None = None,
                 private: bool = False, clone_owner: str | None = None) -> dict:
    """A Forgejo push webhook body for `owner/repo` (clone URL from `clone_owner`, to forge one)."""
    return {"ref": ref, "before": "0" * 40, "after": after or hashlib.sha1(os.urandom(8)).hexdigest(),
            "repository": {"name": repo, "full_name": f"{owner}/{repo}", "private": private,
                           "clone_url": f"{FORGE}/{clone_owner or owner}/{repo}.git",
                           "owner": {"login": owner}}}


# --- waiting on the public site -------------------------------------------------------------------------
def wait_for_body(url: str, needle: str, timeout: float = 90) -> float:
    """Seconds until a verified-TLS GET of `url` returns 200 containing `needle`. git-pages caches a site
    for 60 s, so allow 90. The failure message names only the URL."""
    start = time.monotonic()
    while True:
        with contextlib.suppress(requests.RequestException):
            r = requests.get(url, timeout=10)
            if r.status_code == 200 and needle in r.text:
                return time.monotonic() - start
        if time.monotonic() - start > timeout:
            raise AssertionError(f"{url} did not serve the expected body within {timeout:.0f}s")
        time.sleep(3)


def wait_for_status(url: str, code: int, timeout: float = 90) -> float:
    """Seconds until a GET of `url` (no redirects) answers `code`; same 60 s cache window as wait_for_body."""
    start = time.monotonic()
    last = None
    while True:
        with contextlib.suppress(requests.RequestException):
            last = requests.get(url, allow_redirects=False, timeout=10).status_code
            if last == code:
                return time.monotonic() - start
        if time.monotonic() - start > timeout:
            raise AssertionError(f"{url} did not answer {code} within {timeout:.0f}s (last: {last})")
        time.sleep(3)


# --- galaxy: port-forward, metrics, git-pages admin CLI, alerts -----------------------------------------
@contextlib.contextmanager
def port_forward(svc: str, port: int) -> Iterator[int]:
    """`kubectl -n pages port-forward svc/<svc> 0:<port>`; yields the local port."""
    kubeconfig = os.environ.get("KUBECONFIG", "/tmp/galaxy-kubeconfig")
    proc = subprocess.Popen(["kubectl", "-n", "pages", "port-forward", f"svc/{svc}", f"0:{port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={**os.environ, "KUBECONFIG": kubeconfig})
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 20)
        line = proc.stdout.readline() if ready else ""
        m = re.search(r"127\.0\.0\.1:(\d+)", line)
        if not m:
            proc.terminate()
            raise AssertionError(f"port-forward to svc/{svc} failed: {proc.stderr.read()[-300:]}")
        yield int(m.group(1))
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)


def metrics(svc: str, port: int) -> dict[str, float]:
    """The service's /metrics as {"name{labels}": value} (Prometheus text, comments dropped)."""
    with port_forward(svc, port) as local:
        text = requests.get(f"http://127.0.0.1:{local}/metrics", timeout=15).text
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, val = line.rpartition(" ")
            with contextlib.suppress(ValueError):
                out[key] = float(val)
    return out


def msum(m: dict[str, float], name: str) -> float:
    """Sum of every series of metric `name`, whatever its labels."""
    return sum(v for k, v in m.items() if k == name or k.startswith(name + "{"))


def relay_metrics() -> dict[str, float]:
    return metrics("pages-relay", 8080)


def git_pages_metrics() -> dict[str, float]:
    return metrics("git-pages", 3002)


def outcome(m: dict[str, float], name: str) -> float:
    return m.get(f'pages_relay_events_total{{outcome="{name}"}}', 0.0)


def wait_for_outcome(name: str, at_least: float, timeout: float = 90) -> dict[str, float]:
    """Poll the relay's counter for `name` until it reaches `at_least`; returns the metrics seen."""
    deadline = time.monotonic() + timeout
    while True:
        m = relay_metrics()
        if outcome(m, name) >= at_least:
            return m
        if time.monotonic() > deadline:
            raise AssertionError(f"relay outcome {name} stayed below {at_least:.0f} for {timeout:.0f}s")
        time.sleep(5)


def _git_pages_admin(*args: str) -> str:
    """Run the git-pages admin CLI in its pod; returns stdout+stderr. The config sets log-format = json, so
    CLI messages are JSON log lines: callers match substrings and assert effects, not exact words."""
    r = kube("-n", "pages", "exec", "deploy/git-pages", "--", "git-pages", "-config", GIT_PAGES_CONFIG, *args)
    return (r.stdout + r.stderr).strip()


def takedown(site: str) -> str:
    """Delete a site (`<domain>[/<project>]`) with `-delete-site`; returns the CLI's output. A site that is
    already gone may report an error: that is the caller's to tolerate."""
    return _git_pages_admin("-delete-site", site)


def freeze(domain: str) -> None:
    _git_pages_admin("-freeze-domain", domain)


def unfreeze(domain: str) -> None:
    _git_pages_admin("-unfreeze-domain", domain)


def firing_alerts() -> set[str]:
    """Names of Prometheus alerts that are firing now (read through the prometheus pod: no ingress needed)."""
    pod = kube("-n", "prometheus", "get", "pod", "-l", "app.kubernetes.io/name=prometheus",
               "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
    assert pod, "no prometheus pod"
    out = kube("-n", "prometheus", "exec", pod, "-c", "prometheus", "--", "wget", "-qO-",
               "http://localhost:9090/api/v1/alerts").stdout
    return {a["labels"]["alertname"] for a in json.loads(out)["data"]["alerts"] if a["state"] == "firing"}


# --- posting webhooks -----------------------------------------------------------------------------------
def post_relay(payload: dict, *, sig: str | None = None, event: str = "push") -> requests.Response:
    """POST `payload` to the relay's /hook (in-cluster, through a port-forward). Forgejo's signature is the
    lowercase hex HMAC-SHA256 of the raw body, no prefix, in X-Forgejo-Signature; signed with
    PAGES_WEBHOOK_SECRET unless `sig` is given."""
    body = json.dumps(payload).encode()
    if sig is None:
        sig = hmac.new(webhook_secret().encode(), body, hashlib.sha256).hexdigest()
    with port_forward("pages-relay", 8080) as local:
        return requests.post(f"http://127.0.0.1:{local}/hook", data=body, timeout=15,
                             headers={"X-Forgejo-Event": event, "X-Forgejo-Signature": sig,
                                      "Content-Type": "application/json"})


def post_git_pages(*, host: str, path: str, payload: dict) -> requests.Response:
    """POST straight to git-pages (in-cluster) as if Forgejo had called `https://<host><path>`."""
    with port_forward("git-pages", 3000) as local:
        return requests.post(f"http://127.0.0.1:{local}{path}", json=payload, timeout=15,
                             headers={"Host": host, "X-Forgejo-Event": "push"})


def from_vps_head(url: str) -> str:
    """Response headers of `url` fetched from the VPS: the path a visitor on the internet takes."""
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", VPS,
                        f"curl -sSI --max-time 20 {shlex.quote(url)}"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"curl from the VPS failed: {r.stderr[-200:]}"
    return r.stdout


# --- the system webhook ---------------------------------------------------------------------------------
def ensure_system_hook() -> dict:
    """Idempotently make exactly one active system webhook for RELAY_URL (push, delete, repository; branch
    filter `pages`; signed with PAGES_WEBHOOK_SECRET). Returns {id, active, events, branch_filter}: never
    the config, which holds the secret."""
    want = {"type": "forgejo", "active": True, "events": HOOK_EVENTS, "branch_filter": "pages",
            "config": {"url": RELAY_URL, "content_type": "json", "secret": webhook_secret()}}
    hooks = forge_api("GET", "/api/v1/admin/hooks").json()
    mine = [h for h in hooks if h["config"].get("url") == RELAY_URL]
    if mine:
        r = forge_api("PATCH", f"/api/v1/admin/hooks/{mine[0]['id']}", json=want)
    else:
        r = forge_api("POST", "/api/v1/admin/hooks", json=want)
    assert r.status_code in (200, 201), f"system hook upsert gave {r.status_code}"
    h = r.json()
    return {k: h[k] for k in ("id", "active", "events", "branch_filter")}
