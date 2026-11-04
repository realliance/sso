"""Helpers for the forge acceptance suite (tests/forge/): git.realliance.net, its SSO sign-in, SSH and
B2. Secrets come from the unlocked realliance/sso-secrets checkout and never reach argv or output."""
import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable
from html import unescape
from pathlib import Path
from urllib.parse import urlencode, urlparse

import pytest
import requests
import yaml

from conftest import (REALM, SECRETS_DIR, SSO, User, _form_action, _load_env, admin_token, get, group_id,
                      put, totp)

FORGE = "https://git.realliance.net"
FORGE_SECRETS = SECRETS_DIR / "forge/secrets.env"
VPS = "root@23.163.0.48"          # the SSO box: our vantage point on the internet
WAN_IP = "152.44.247.88"          # galaxy's WAN address (DHCP; hardcoded in the router's reflection rules)
FORGE_LB = "192.168.0.6"          # Forgejo's SSH LoadBalancer
# The luma-homeops checkout the manifest tests read. LUMA_HOMEOPS points them at a worktree, so a
# branch can be tested before it reaches main.
LUMA = Path(os.environ.get("LUMA_HOMEOPS", Path.home() / "Repos/luma-homeops"))
INVENTORY = "realliance-ops/forge"          # the forge inventory (OpenTofu), in the Owners-only org
# The forge's bots, in realliance-ops since 2026-11-04 (luma-homeops plan bots-to-realliance-ops), so that
# only its Owners can push a branch that runs on the galaxy runner.
FORGE_BOT_REPO = "realliance-ops/forge-bot"
CI_DISPATCH_REPO = "realliance-ops/ci-dispatch"
CYCLE_WAIT = 2 * 300 + 60                   # two forge-bot cycles (every 5 min ± 30 s) and slack


def forge_api(method: str, path: str, *, token: str | None = None, sudo: str | None = None,
              **kw) -> requests.Response:
    """Forgejo API call; `token=None` means the break-glass admin's token, `sudo` acts as that user."""
    token = token or _load_env(FORGE_SECRETS)["FORGEJO_ADMIN_TOKEN"]
    headers = {"Authorization": f"token {token}", **({"Sudo": sudo} if sudo else {})}
    return requests.request(method, f"{FORGE}{path}", headers=headers, timeout=30, **kw)


def _paged(path: str, limit: int = 50) -> list[dict]:
    """Every item of a paged Forgejo list endpoint, as the admin (50 is Forgejo's default page cap)."""
    items, page = [], 1
    while True:
        r = forge_api("GET", path, params={"page": page, "limit": limit})
        r.raise_for_status()
        batch = r.json()
        items += batch
        if len(batch) < limit:
            return items
        page += 1


def team_members(org: str, team: str) -> set[str]:
    """Logins in `org`'s team `team` (every page)."""
    tid = next((t["id"] for t in _paged(f"/api/v1/orgs/{org}/teams") if t["name"] == team), None)
    if tid is None:
        raise LookupError(f"no team {team!r} in org {org!r}")
    return {m["login"] for m in _paged(f"/api/v1/teams/{tid}/members")}


def wait_for(pred: Callable[[], bool], timeout: float = CYCLE_WAIT, every: float = 10) -> bool:
    """True as soon as `pred()` is true, False once `timeout` seconds have passed. A falsy result never
    raises; an exception from `pred` does."""
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        time.sleep(min(every, left))


def _next_totp(user: User) -> str:
    # Keycloak refuses a replayed code and accepts the next window (look-ahead 1): never reuse a window.
    now = int(time.time() // 30)
    want = max(now, (user.totp_counter if user.totp_counter is not None else -1) + 1)
    if want > now + 1:
        time.sleep((want - 1) * 30 - time.time() + 1)
    user.totp_counter = want
    return totp(user.totp_secret, at=want * 30)


def forge_login_attempt(user: User) -> tuple[requests.Session, requests.Response]:
    """Sign in to Forgejo through Realliance SSO like a browser (password, then TOTP: enrolment the
    first time, a code afterwards). Returns the session and the final response, without asserting."""
    s = requests.Session()
    page = s.get(f"{FORGE}/user/oauth2/realliance", timeout=30)
    if urlparse(page.url).hostname != urlparse(SSO).hostname:
        return s, page
    r = s.post(_form_action(page.text), data={"username": user.name, "password": user.pw},
               allow_redirects=False, timeout=30)
    for _ in range(10):
        if r.status_code in (301, 302, 303, 307):
            loc = r.headers["Location"]
            if urlparse(loc).hostname not in (None, urlparse(SSO).hostname):
                return s, s.get(loc, timeout=30)          # back to Forgejo: let it finish the callback
            r = s.get(requests.compat.urljoin(r.url, loc), allow_redirects=False, timeout=30)
        elif 'name="totpSecret"' in r.text:              # first sign-in: enrol TOTP
            user.totp_secret = unescape(re.search(r'name="totpSecret" value="([^"]+)"', r.text).group(1))
            r = s.post(_form_action(r.text), allow_redirects=False, timeout=30,
                       data={"totp": _next_totp(user), "totpSecret": user.totp_secret, "userLabel": "test"})
        elif 'name="otp"' in r.text and user.totp_secret:  # later sign-ins: a code
            r = s.post(_form_action(r.text), data={"otp": _next_totp(user)}, allow_redirects=False, timeout=30)
        else:
            return s, r                                   # an SSO page we don't answer (refusal, error)
    return s, r


def forge_signed_in(session: requests.Session) -> bool:
    """A working session sees its profile form. Signed out redirects; a prohibited account gets a
    200 "Account is suspended" page instead, so the status code alone is not enough."""
    r = session.get(f"{FORGE}/user/settings", allow_redirects=False, timeout=30)
    return r.status_code == 200 and 'name="full_name"' in r.text


def forge_login(user: User) -> requests.Session:
    s, r = forge_login_attempt(user)
    assert urlparse(r.url).hostname == urlparse(FORGE).hostname, f"sign-in ended at {r.url} ({r.status_code})"
    assert forge_signed_in(s), "Forgejo did not start a session"
    return s


def forge_relogin(session: requests.Session, user: User) -> requests.Session:
    """Sign in again through SSO (Forgejo re-reads groups only at sign-in). The old session is left as is."""
    return forge_login(user)


def forge_token(session: requests.Session, name: str, scopes: list[str]) -> str:
    """Create a personal access token through the settings form (there is no password for the API).
    Forgejo 15 has no CSRF tokens: it checks Fetch metadata, which a non-browser client doesn't send."""
    r = session.post(f"{FORGE}/user/settings/applications/tokens/new", timeout=30,
                     data=[("name", name), ("resource", "all")] + [("scope", sc) for sc in scopes])
    flash = r.text.split(' flash-info"', 1)  # <div … class="ui info message flash-message flash-info">
    m = re.search(r"\b([0-9a-f]{40})\b", flash[1][:2000]) if len(flash) == 2 else None
    assert m, f"no new token on the page ({r.status_code} {r.url})"
    return m.group(1)


def ssh_keyscan(host: str, *, via: str | None = None, port: int = 22) -> str:
    """Every host key the server offers ("ssh-rsa AAAA…" lines, sorted), scanned locally or from `via`
    ("" if none). Forgejo's built-in server offers RSA only (gitea.rsa), so compare whole sets."""
    cmd = ["ssh-keyscan", "-T", "10", "-p", str(port), "-t", "rsa,ecdsa,ed25519", host]
    if via:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", via, " ".join(cmd)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    return "\n".join(sorted({" ".join(line.split()[1:3]) for line in out.splitlines()
                              if line and not line.startswith("#")}))


def on_lan() -> bool:
    out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
    return " 192.168.0." in out


lan_only = pytest.mark.skipif(not on_lan(), reason="needs the galaxy LAN (192.168.0.0/24)")


def b2_names(bucket: str, prefix: str) -> list[dict]:
    """Current files under prefix in a Realliance B2 bucket: name, size, uploadTimestamp (ms)."""
    env = _load_env(SECRETS_DIR / "b2/secrets.env")
    auth = requests.get("https://api.backblazeb2.com/b2api/v4/b2_authorize_account", timeout=20,
                        auth=(env["B2_APPLICATION_KEY_ID"], env["B2_APPLICATION_KEY"])).json()
    api, tok = auth["apiInfo"]["storageApi"]["apiUrl"], auth["authorizationToken"]

    def call(name, body):
        r = requests.post(f"{api}/b2api/v4/{name}", headers={"Authorization": tok}, json=body, timeout=30)
        r.raise_for_status()
        return r.json()

    bucket_id = next(b["bucketId"] for b in call("b2_list_buckets", {"accountId": auth["accountId"]})["buckets"]
                     if b["bucketName"] == bucket)
    files, start = [], None
    while True:
        page = call("b2_list_file_names", {"bucketId": bucket_id, "prefix": prefix, "maxFileCount": 1000,
                                           **({"startFileName": start} if start else {})})
        files += [{"name": f["fileName"], "size": f["contentLength"], "uploadTimestamp": f["uploadTimestamp"]}
                  for f in page["files"]]
        start = page.get("nextFileName")
        if not start:
            return files


def set_groups(user: User, paths: list[str]) -> None:
    """Replace the Keycloak user's groups (what an sso-people change does)."""
    token = admin_token()
    base = f"/admin/realms/{REALM}/users/{user.id}/groups"
    for g in get(base, token).json():
        requests.delete(f"{SSO}{base}/{g['id']}", headers={"Authorization": f"Bearer {token}"}, timeout=20)
    for p in paths:
        r = put(f"{base}/{group_id(p)}", token)
        assert r.status_code == 204, r.text


def kc_groups_named(name: str) -> list[dict]:
    """Top-level Keycloak groups (realm groups, as in the groups claim) whose name is exactly `name`."""
    r = get(f"/admin/realms/{REALM}/groups", admin_token(), params={"search": name, "exact": "true"})
    r.raise_for_status()
    return [g for g in r.json() if g["name"] == name]


def set_email(user: User, email: str) -> None:
    token = admin_token()
    rep = get(f"/admin/realms/{REALM}/users/{user.id}", token).json()
    rep.update(email=email, emailVerified=True)
    r = put(f"/admin/realms/{REALM}/users/{user.id}", token, rep)
    assert r.status_code == 204, r.text


PACKAGE_TOKEN_REPO_SCOPED = False   # B0 outcome B: Forgejo has no repository-scoped tokens reachable (no CLI option; token API refuses sudo), so forge-ci holds a plain write:package token


def anonymous_manifest(image: str, tag: str) -> requests.Response:
    """The image's manifest fetched with no credentials at all (public package => 200)."""
    r = requests.get(f"{FORGE}/v2/{image}/manifests/{tag}", timeout=30, headers={"Accept": _OCI_MANIFEST})
    if r.status_code == 401:    # the registry hands out anonymous pull tokens for public images
        tok = _bearer(r.headers["WWW-Authenticate"], None)
        r = requests.get(f"{FORGE}/v2/{image}/manifests/{tag}", timeout=30,
                         headers={"Accept": _OCI_MANIFEST, **({"Authorization": f"Bearer {tok}"} if tok else {})})
    return r


_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def _bearer(challenge: str, auth: tuple[str, str] | None, scope: str | None = None) -> str | None:
    """Follow a `WWW-Authenticate: Bearer realm=…,service=…` challenge; the credentials only ever
    travel as request auth. None when the token endpoint refuses."""
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.pop("realm")
    assert realm.startswith(FORGE + "/"), "registry token realm is not the forge"   # never send credentials elsewhere
    if scope:
        params["scope"] = scope
    r = requests.get(realm, params=params, auth=auth, timeout=30)
    return r.json().get("token") or r.json().get("access_token") if r.status_code == 200 else None


def oci_push(image: str, tag: str, user: str, token: str) -> int:
    """Push a tiny one-layer OCI image to the forge registry over the plain distribution API (no
    docker/podman). Returns the manifest PUT's status, or the status of whichever earlier step
    (token, blob upload) refused."""
    import hashlib
    import json

    def blob(data: bytes) -> tuple[str, bytes]:
        return "sha256:" + hashlib.sha256(data).hexdigest(), data

    cfg_d, cfg = blob(json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode())
    lay_d, lay = blob(b"b0 probe layer\n")
    base = f"{FORGE}/v2/{image}"
    probe = requests.post(f"{base}/blobs/uploads/", timeout=30)
    if probe.status_code != 401:
        return probe.status_code
    bearer = _bearer(probe.headers["WWW-Authenticate"], (user, token), f"repository:{image}:push,pull")
    if bearer is None:
        return 401
    h = {"Authorization": f"Bearer {bearer}"}
    for digest, data in ((cfg_d, cfg), (lay_d, lay)):
        r = requests.post(f"{base}/blobs/uploads/", headers=h, timeout=30)
        if r.status_code != 202:
            return r.status_code
        loc = r.headers["Location"]
        loc = loc if loc.startswith("http") else FORGE + loc
        r = requests.put(loc, params={"digest": digest}, data=data, timeout=60,
                         headers={**h, "Content-Type": "application/octet-stream"})
        if r.status_code != 201:
            return r.status_code
    manifest = {"schemaVersion": 2, "mediaType": _OCI_MANIFEST,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_d, "size": len(cfg)},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": lay_d, "size": len(lay)}]}
    return requests.put(f"{base}/manifests/{tag}", data=json.dumps(manifest), timeout=30,
                        headers={**h, "Content-Type": _OCI_MANIFEST}).status_code


# --- galaxy (kubectl) and Forgejo Actions ------------------------------------------------------------
KUBECONFIG = os.environ.get("KUBECONFIG", "/tmp/galaxy-kubeconfig")
PROBE_WORKFLOW = ".forgejo/workflows/probe.yaml"


def kube(*args: str, stdin: str | None = None, timeout: float = 300) -> subprocess.CompletedProcess:
    """`kubectl <args>` against galaxy (KUBECONFIG, default /tmp/galaxy-kubeconfig), output captured.
    A value handed over on `stdin` never reaches argv."""
    return subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "KUBECONFIG": KUBECONFIG})


def _galaxy_reachable() -> bool:
    if shutil.which("kubectl") is None:
        return False
    try:
        return kube("--request-timeout=10s", "get", "--raw", "/readyz", timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


galaxy_only = pytest.mark.skipif(not _galaxy_reachable(), reason="needs kubectl and the galaxy cluster")

PROM_API = "/api/v1/namespaces/prometheus/services/prometheus-kube-prometheus-prometheus:9090/proxy/api/v1"


def prom_query(expr: str) -> list[dict]:
    """An instant PromQL query against galaxy's Prometheus, through the API server's service proxy
    (read-only). Returns data.result: [{"metric": {...}, "value": [ts, "v"]}, ...]."""
    r = kube("get", "--raw", f"{PROM_API}/query?{urlencode({'query': expr})}", timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"prometheus query failed (exit {r.returncode}): {r.stderr.strip()[:300]}")
    body = json.loads(r.stdout)
    if body.get("status") != "success":
        raise RuntimeError(f"prometheus query {expr!r}: {body.get('error', body)}")
    return body["data"]["result"]


def firing(alertname: str) -> list[dict]:
    """Label sets of the `alertname` alerts firing now (pending ones are not firing)."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alertname):
        raise ValueError(f"not an alert name: {alertname!r}")
    return [x["metric"] for x in prom_query(f'ALERTS{{alertname="{alertname}",alertstate="firing"}}')]


def manifests(d: Path) -> list[dict]:
    """Every Kubernetes object (a YAML document with a `kind`) in d/*.yaml, skipping *.secret.yaml:
    those are git-crypt files, decrypted on this machine. A kind-less document, such as forge-bot's
    own config.yaml or its promtool tests, is not an object and is left out (pre-flight #7)."""
    docs = []
    for p in sorted(d.glob("*.yaml")):
        if not p.name.endswith(".secret.yaml"):
            docs += [x for x in yaml.safe_load_all(p.read_text()) if isinstance(x, dict) and "kind" in x]
    return docs


def assert_pod_hardened(spec: dict) -> None:
    """The Global Constraints' pod rules, on a pod template spec: no service-account token or service
    links, no host namespaces or hostPath, non-root with RuntimeDefault seccomp, and every container
    unprivileged, without escalation, with every capability dropped and no Docker socket. Shared by
    the runner and forge-bot tests (pre-flight #19)."""
    assert spec["automountServiceAccountToken"] is False and spec["enableServiceLinks"] is False
    assert not any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC"))
    assert not any("hostPath" in v for v in spec.get("volumes", []))
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    for c in spec["containers"] + spec.get("initContainers", []):
        sc = c["securityContext"]
        assert sc.get("privileged") is not True and sc["allowPrivilegeEscalation"] is False
        assert sc["capabilities"] == {"drop": ["ALL"]} and "docker.sock" not in yaml.safe_dump(c)


def push_probe_workflow(repo: str, runs_on: str, script: str, branch: str | None = None) -> tuple[str, str]:
    """Commit PROBE_WORKFLOW (on: push to ci-probe-*, one job on `runs_on` running `script`) through the
    contents API as the admin: on a new branch ci-probe-<hex> off the default branch, or as one more
    commit on `branch`. Returns (branch, commit sha). No git subprocess, so no local git config applies."""
    wf = {"name": f"ci-probe {secrets.token_hex(3)}",          # differs per commit, so every push changes the file
          "on": {"push": {"branches": ["ci-probe-*"]}},
          "jobs": {"probe": {"runs-on": runs_on, "steps": [{"run": script}]}}}
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


def delete_branch(repo: str, branch: str) -> None:
    """Best effort: a branch that is already gone is fine."""
    forge_api("DELETE", f"/api/v1/repos/{repo}/branches/{branch}")


def runs_for(repo: str, sha: str) -> list[dict]:
    """The repo's Actions runs for commit `sha`."""
    r = forge_api("GET", f"/api/v1/repos/{repo}/actions/runs", params={"head_sha": sha, "limit": 50})
    r.raise_for_status()
    return r.json()["workflow_runs"]
