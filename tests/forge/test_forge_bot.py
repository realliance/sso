"""Forge bot accounts: forge-bot (site admin) is a local Forgejo account whose API token carries admin scopes but
cannot create repositories. forge-ci is retired (2026-11-04): login prohibited, in no team.

Also forge-bot's deployment on galaxy (luma-homeops cluster/forge-bot): a hardened single pod running the
reviewed, digest-pinned image with every job in dry-run, a public-safe config, the Owners' public keyring, its
alerts and scrape wiring, and its egress policy. The static tests read LUMA (set LUMA_HOMEOPS to test a
luma-homeops worktree); the galaxy_only ones read the cluster and Prometheus."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

import requests
import yaml

from conftest import REPO, SSO, _load_env
from forge_helpers import (FORGE, FORGE_BOT_REPO, FORGE_SECRETS, INVENTORY, LUMA, anonymous_manifest,
                           assert_pod_hardened, firing, forge_api, galaxy_only, kube, manifests, prom_query,
                           runs_for)

BOT_DIR = LUMA / "cluster/forge-bot"
JOBS = {"access", "admin", "teams", "profile", "avatar"}
IMAGE = re.compile(r"git\.realliance\.net/realliance-ops/forge-bot:sha-([0-9a-f]{7})@(sha256:[0-9a-f]{64})")
CHRIS_FPR = "E9245FED84E0EC721C7B5C336BFB8037115ADE26"
ARMORED_KEY = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.S)
# Never reachable on the HTTPS rule: the NetworkPolicy spec's not-internet set (§6.3: unroutable 0/8,
# 127/8 and 240/4, pods and Services, the LAN with nodes, BMCs and LB IPs, the other private range, the
# tailnet, link-local, multicast) plus galaxy's WAN /25, whose :443 the router reflects to Traefik.
NOT_INTERNET = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "152.44.247.0/25"]
# Prometheus keeps only these series from forge-bot's scrape: honorLabels lets the target set its own job
# and namespace labels, so it may add nothing but its own metrics (review M4).
KEEP = r"forge_bot_.*|go_.*|process_.*|promhttp_.*"
PROMQL_WORDS = {"and", "or", "unless", "bool", "offset", "inf", "nan"}
CRITICAL = ["ForgeBotBreakerTripped", "ReallianceSSOUnreadable", "ForgeBotOwnerNeedsAction",
            "ForgeBotUnexpectedSSOWrite", "ForgeBotOwnersUnknown"]


def test_bot_accounts_are_local():
    a = forge_api("GET", "/api/v1/users/forge-bot").json()
    assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, True, False)


def test_forge_ci_is_retired():
    a = forge_api("GET", "/api/v1/users/forge-ci").json()
    assert (a["source_id"], a["is_admin"], a["prohibit_login"]) == (0, False, True)
    assert forge_api("GET", "/api/v1/user/teams", sudo="forge-ci").json() == []


def test_forge_bot_token_scopes():
    tok = _load_env(FORGE_SECRETS)["FORGE_BOT_FORGEJO_TOKEN"]
    listing = forge_api("GET", "/api/v1/admin/users", token=tok, params={"limit": 1})
    assert listing.status_code == 200
    create = forge_api("POST", "/api/v1/user/repos", token=tok, json={"name": "nope"})
    assert create.status_code == 403


# --- the deployment, static ---------------------------------------------------------------------------
def _one(kind: str) -> dict:
    found = [x for x in manifests(BOT_DIR) if x["kind"] == kind]
    assert len(found) == 1, f"want one {kind} in {BOT_DIR}, found {len(found)}"
    return found[0]


def _pinned() -> tuple[str, str]:
    """(the sha-<7> tag's short commit, the sha256 digest) of the image statefulset.yaml pins."""
    images = IMAGE.findall((BOT_DIR / "statefulset.yaml").read_text())
    assert len(images) == 1, images
    return images[0]


def _config() -> dict:
    return yaml.safe_load((BOT_DIR / "config.yaml").read_text())


def test_manifests_lists_objects_only(tmp_path):                  # pre-flight #7
    (tmp_path / "config.yaml").write_text("sso:\n  url: x\n")
    (tmp_path / "list.yaml").write_text("- a\n---\n# empty\n---\nkind: Service\n")
    (tmp_path / "s.secret.yaml").write_text("kind: Secret\n")
    assert manifests(tmp_path) == [{"kind": "Service"}]
    assert manifests(BOT_DIR) and all("kind" in x for x in manifests(BOT_DIR))


def test_forge_bot_kustomization_ships_every_object():
    k = yaml.safe_load((BOT_DIR / "kustomization.yaml").read_text())
    assert k["namespace"] == "forge-bot"
    objects = {p.name for p in BOT_DIR.glob("*.yaml") if not p.name.endswith(".secret.yaml")
               and any(isinstance(x, dict) and "kind" in x for x in yaml.safe_load_all(p.read_text()))}
    objects.discard("kustomization.yaml")
    assert set(k["resources"]) == objects
    # Hash-suffixed (nothing turns the suffix off), so a config or keyring change restarts the pod.
    gens = {g["name"]: g["files"] for g in k["configMapGenerator"]}
    assert gens == {"forge-bot-config": ["config.yaml"],
                    "forge-bot-keyring": ["keyring/owners.asc", "keyring/fingerprints.txt"]}
    assert not k.get("generatorOptions", {}).get("disableNameSuffixHash")
    app = yaml.safe_load((LUMA / "cluster/applications/forge-bot.yaml").read_text())
    assert (app["spec"]["source"]["path"], app["spec"]["destination"]["namespace"]) == ("cluster/forge-bot", "forge-bot")
    apps = yaml.safe_load((LUMA / "cluster/applications/kustomization.yaml").read_text())["resources"]
    assert "forge-bot.yaml" in apps


def test_forge_bot_manifests_hardened():                          # Success 17
    ns = _one("Namespace")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "baseline"
    # At most one bot, through drains and node loss too (review I1): the StatefulSet controller never
    # creates forge-bot-0 while the old forge-bot-0 object exists. A Deployment's ReplicaSet would.
    assert not [x for x in manifests(BOT_DIR) if x["kind"] in ("Deployment", "ReplicaSet", "DaemonSet", "Pod")]
    sts = _one("StatefulSet")
    assert sts["metadata"]["name"] == "forge-bot" and sts["spec"]["replicas"] == 1
    assert sts["spec"]["serviceName"] == _one("Service")["metadata"]["name"] == "forge-bot"
    assert sts["spec"]["updateStrategy"] == {"type": "RollingUpdate"}       # delete forge-bot-0, then recreate it
    assert "volumeClaimTemplates" not in sts["spec"] and sts["spec"].get("podManagementPolicy", "OrderedReady") == "OrderedReady"
    # The price of at-most-one, written where the operator looks.
    docs = " ".join((LUMA / "docs/forgejo.md").read_text().split())     # wrapping-proof
    assert "force-deletes the pod after confirming the node is off (S4)" in docs and "ForgeBotStale fires meanwhile" in docs
    spec = sts["spec"]["template"]["spec"]
    assert_pod_hardened(spec)
    sc = spec["securityContext"]
    assert (sc["runAsUser"], sc["runAsGroup"], sc["fsGroup"]) == (65532, 65532, 65532)   # pre-flight #2
    assert spec["terminationGracePeriodSeconds"] == 35          # 25 s write grace + 5 s HTTP shutdown
    (c,) = spec["containers"]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert IMAGE.fullmatch(c["image"]), c["image"]
    assert c["args"] == ["--config=/etc/forge-bot/config/config.yaml"]
    assert c["resources"] == {"requests": {"cpu": "20m", "memory": "32Mi"}, "limits": {"memory": "256Mi"}}
    assert c["env"] == [{"name": "GOMEMLIMIT", "value": "192MiB"}]   # 3/4 of the limit (M10 sizing)
    assert c["ports"] == [{"name": "http", "containerPort": 8080}]
    # /healthz serves only after CheckSource (5 min budget), then answers 503 only when no cycle of any
    # outcome finished in 15 min: liveness restarts a wedged loop, never a slow or failing one.
    assert c["startupProbe"] == {"httpGet": {"path": "/healthz", "port": "http"},
                                 "periodSeconds": 10, "timeoutSeconds": 5, "failureThreshold": 30}
    assert c["livenessProbe"] == {"httpGet": {"path": "/healthz", "port": "http"},
                                  "periodSeconds": 60, "timeoutSeconds": 5, "failureThreshold": 2}
    assert "readinessProbe" not in c
    mounts = {m["mountPath"]: (m["name"], m.get("readOnly")) for m in c["volumeMounts"]}
    assert mounts == {"/etc/forge-bot/config": ("config", True), "/etc/forge-bot/keyring": ("keyring", True),
                      "/etc/forge-bot/secrets": ("secrets", True)}
    vols = {v["name"]: v for v in spec["volumes"]}
    assert vols["config"]["configMap"]["name"] == "forge-bot-config"
    assert vols["keyring"]["configMap"]["name"] == "forge-bot-keyring"
    proj = vols["secrets"]["projected"]
    assert proj["defaultMode"] == 0o400
    assert [(s["secret"]["name"], s["secret"]["items"]) for s in proj["sources"]] == [
        ("forge-bot-forgejo", [{"key": "forgejo-token", "path": "forgejo-token"}]),
        ("forge-bot-keycloak", [{"key": "keycloak-client-secret", "path": "keycloak-client-secret"}])]
    sealed = {x["spec"]["template"]["metadata"]["name"]: set(x["spec"]["encryptedData"])
              for x in manifests(BOT_DIR) if x["kind"] == "SealedSecret"}
    assert sealed == {"forge-bot-forgejo": {"forgejo-token"}, "forge-bot-keycloak": {"keycloak-client-secret"}}


def test_forge_bot_config_public_safe():
    cfg = _config()
    # Each job's intended mode, exactly (review M5): every job in dry-run until T17 moves one at a time,
    # changing this line with it.
    assert cfg["modes"] == {"access": "dry-run", "admin": "dry-run", "teams": "dry-run", "profile": "dry-run",
                            "avatar": "dry-run"}
    assert cfg["inventory"]["repo"] == INVENTORY and cfg["forgejo"]["source_id"] == 1
    # Public groups only; hidden names never appear in luma-homeops.
    assert (cfg["sso"]["access_group"], cfg["sso"]["admin_group"]) == ("/apps/forgejo", "/forgejo-admins")
    # The default 1/3 applies only when the key is absent: a decimal 0.33 lowers the cap for 9 people to 2.
    assert "loss_fraction" not in cfg.get("limits", {})
    # Canonical URLs: both clients pin the exact scheme and host[:port].
    assert (cfg["sso"]["url"], cfg["forgejo"]["public_url"]) == (SSO, FORGE)
    assert cfg["forgejo"]["url"] == "http://forgejo-http.forgejo.svc.cluster.local:3000"
    for url in (cfg["sso"]["url"], cfg["forgejo"]["url"], cfg["forgejo"]["public_url"]):
        u = urlsplit(url)
        default = {"http": 80, "https": 443}[u.scheme]
        assert u.netloc == u.netloc.lower() and u.port != default and f"{u.scheme}://{u.netloc}" == url, url
    # The files the config names are the ones the pod mounts.
    assert cfg["sso"]["client_secret_file"] == "/etc/forge-bot/secrets/keycloak-client-secret"
    assert cfg["forgejo"]["token_file"] == "/etc/forge-bot/secrets/forgejo-token"
    assert (cfg["inventory"]["keyring"], cfg["inventory"]["fingerprints"]) == (
        "/etc/forge-bot/keyring/owners.asc", "/etc/forge-bot/keyring/fingerprints.txt")
    assert cfg["listen"] == ":8080"


def _gpg_records(armored: str) -> list[list[str]]:
    """gpg's colon listing of `armored`, show-only in a throwaway home: nothing is imported anywhere."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        r = subprocess.run(["gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import"],
                           input=armored, capture_output=True, text=True, timeout=60,
                           env={**os.environ, "GNUPGHOME": home})
    assert r.returncode == 0, r.stderr[-300:]
    return [line.split(":") for line in r.stdout.splitlines()]


def test_forge_bot_keyring_is_owners_public_keys():
    # owners.asc: Owners' PUBLIC keys only, each a byte-for-byte copy of keys/<name>.asc in this repo (never
    # GitHub's web-flow key), with nothing around them (the loader refuses stray text); fingerprints.txt
    # allow-lists exactly their primary keys, "# name" comments allowed (pre-flight #17).
    asc = (BOT_DIR / "keyring/owners.asc").read_text()
    blocks = ARMORED_KEY.findall(asc)
    assert blocks and ARMORED_KEY.sub("", asc).strip() == ""
    people = {p.read_text().strip() for p in (REPO / "keys").glob("*.asc") if p.name != "github-web-flow.asc"}
    assert all(b.strip() in people for b in blocks)
    records = _gpg_records(asc)
    assert not any(rec[0] in ("sec", "ssb") for rec in records), "private key material in the keyring"
    primaries = [records[i + 1][9] for i, rec in enumerate(records[:-1]) if rec[0] == "pub" and records[i + 1][0] == "fpr"]
    listed = [f.upper() for f in ("".join(line.split("#", 1)[0].split())
                                  for line in (BOT_DIR / "keyring/fingerprints.txt").read_text().splitlines()) if f]
    assert sorted(listed) == sorted(primaries) and len(primaries) == len(blocks) and CHRIS_FPR in listed


def test_forge_bot_networkpolicy():
    # Default deny both ways (review M1). In: only Prometheus's namespace, on the metrics port (kubelet
    # probes come from root on the node, which the enforcer exempts). Out (NetworkPolicy plan F1): DNS, the
    # Forgejo pods behind forgejo-http, and HTTPS to public addresses (sso.realliance.net is behind
    # Cloudflare, so not the SSO box's 23.163.0.48/32). Nothing else.
    np = _one("NetworkPolicy")
    spec = np["spec"]
    assert spec["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "forge-bot"}}
    pod_spec = _one("StatefulSet")["spec"]["template"]
    assert spec["podSelector"]["matchLabels"].items() <= pod_spec["metadata"]["labels"].items()
    assert spec["policyTypes"] == ["Ingress", "Egress"]
    metrics_port = next(p["containerPort"] for p in pod_spec["spec"]["containers"][0]["ports"] if p["name"] == "http")
    assert spec["ingress"] == [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "prometheus"}}}],
                                "ports": [{"protocol": "TCP", "port": metrics_port}]}] and metrics_port == 8080
    assert all(rule.get("ports") and rule.get("to") for rule in spec["egress"]), "an egress rule without ports or peers"
    dns, forgejo, https = spec["egress"]
    assert dns["to"] == [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                          "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}]
    assert sorted((p["protocol"], p["port"]) for p in dns["ports"]) == [("TCP", 53), ("UDP", 53)]
    assert forgejo["to"] == [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "forgejo"}},
                              "podSelector": {"matchLabels": {"app.kubernetes.io/name": "forgejo",
                                                              "app.kubernetes.io/instance": "forgejo"}}}]
    assert forgejo["ports"] == [{"protocol": "TCP", "port": 3000}]
    (peer,) = https["to"]
    assert peer["ipBlock"]["cidr"] == "0.0.0.0/0" and set(NOT_INTERNET) <= set(peer["ipBlock"]["except"])
    assert https["ports"] == [{"protocol": "TCP", "port": 443}]
    assert "23.163.0.48" not in yaml.safe_dump(np)


def test_sso_resolves_to_addresses_the_policy_allows():
    # The HTTPS rule is what lets forge-bot reach Keycloak: every address sso.realliance.net resolves to
    # must lie outside the excepts.
    host = urlsplit(_config()["sso"]["url"]).hostname
    addrs = {ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
    blocked = [str(a) for a in addrs if any(a in ipaddress.ip_network(n) for n in NOT_INTERNET)]
    assert addrs and not blocked, f"{host} resolves into a blocked range: {blocked}"


def test_forge_bot_scraped_with_its_own_job_label():
    svc, sm = _one("Service"), _one("ServiceMonitor")
    assert svc["spec"]["selector"] == {"app.kubernetes.io/name": "forge-bot"}
    assert svc["spec"]["ports"] == [{"name": "http", "port": 8080, "targetPort": "http"}]
    assert sm["metadata"]["labels"]["release"] == "prometheus"     # what the serviceMonitorSelector picks
    assert sm["spec"]["selector"]["matchLabels"].items() <= svc["metadata"]["labels"].items()
    (ep,) = sm["spec"]["endpoints"]
    # honorLabels keeps the metrics' own `job` label (access, admin, ...): without it every by (job) and
    # on (job) in the alerts keys on the scrape job (pre-flight #1). It also lets the target set job and
    # namespace on anything it emits, so a keep-list confines it to its own series (review M4).
    assert (ep["port"], ep["path"], ep["interval"], ep["honorLabels"]) == ("http", "/metrics", "60s", True)
    assert ep["metricRelabelings"] == [{"sourceLabels": ["__name__"], "regex": KEEP, "action": "keep"}]


def _metric_names(expr: str) -> set[str]:
    """Metric names a PromQL expression reads: identifiers left after dropping string literals, label
    matchers, range selectors and by/on/without/ignoring label lists, minus keywords and function or
    aggregation calls."""
    expr = re.sub(r'"(?:\\.|[^"\\])*"', '""', expr)
    expr = re.sub(r"\{[^}]*\}|\[[^\]]*\]", " ", expr)
    expr = re.sub(r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", " ", expr)
    # The lookbehind skips a duration's unit (the m of 30m) and a number's exponent.
    return {m.group() for m in re.finditer(r"(?<![A-Za-z0-9_:.])[A-Za-z_:][A-Za-z0-9_:]*", expr)
            if m.group().lower() not in PROMQL_WORDS and not re.match(r"\s*\(", expr[m.end():])}


def test_metric_names_parser():
    assert _metric_names('max by (job) (a_b{x=~"c|d"} and on (job) (e == 2)) > 0') == {"a_b", "e"}
    assert _metric_names("time() - f_ts >= 1500 or absent(g_ts)") == {"f_ts", "g_ts"}
    assert _metric_names('max(increase(h_total[15m])) > 0 unless i offset 30m') == {"h_total", "i"}


def test_keep_list_keeps_every_alert_input():
    # Every metric forge-bot v0.1.0's alert rules read, and every series its promtool tests feed them, as
    # the forge serves both files at the pinned commit, survives the keep-list: no alert loses its input.
    short, _ = _pinned()
    full = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/git/commits/{short}").json()["sha"]
    files = {}
    for name in ("alerts.yaml", "alerts_test.yaml"):
        r = requests.get(f"{FORGE}/{FORGE_BOT_REPO}/raw/commit/{full}/internal/metrics/{name}", timeout=20)
        r.raise_for_status()
        files[name] = yaml.safe_load(r.text)
    used = {n for g in files["alerts.yaml"]["groups"] for x in g["rules"] for n in _metric_names(x["expr"])}
    for t in files["alerts_test.yaml"]["tests"]:
        used |= {re.match(r"[A-Za-z_:][A-Za-z0-9_:]*", s["series"]).group() for s in t.get("input_series", [])}
        used |= {n for e in t.get("promql_expr_test", []) for n in _metric_names(e["expr"])}
    assert {"forge_bot_cycle_last_success_timestamp", "forge_bot_findings", "forge_bot_job_mode"} <= used
    keep = _one("ServiceMonitor")["spec"]["endpoints"][0]["metricRelabelings"][0]["regex"]
    dropped = sorted(n for n in used if not re.fullmatch(keep, n))   # Prometheus anchors relabel regexes
    assert not dropped, f"the keep-list drops alert inputs: {dropped}"


def test_forge_bot_alert_rules_are_the_releases():
    # The PrometheusRule is forge-bot's internal/metrics/alerts.yaml at the pinned image's commit, as the
    # forge serves it (not the plan table's expressions).
    rule = _one("PrometheusRule")
    assert rule["metadata"]["name"] == "forge-bot-alerts"
    assert rule["metadata"]["labels"] == {"prometheus": "kube-prometheus", "role": "alert-rules", "release": "prometheus"}
    short, _ = _pinned()
    full = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/git/commits/{short}").json()["sha"]
    r = requests.get(f"{FORGE}/{FORGE_BOT_REPO}/raw/commit/{full}/internal/metrics/alerts.yaml", timeout=20)
    r.raise_for_status()
    assert rule["spec"] == yaml.safe_load(r.text)
    alerts = [x for g in rule["spec"]["groups"] for x in g["rules"] if "alert" in x]
    exprs = {x["alert"]: x["expr"] for x in alerts}
    assert exprs["ForgeBotInventoryInvalid"] == 'forge_bot_inventory_ok{check=~"teams|bot_config"} == 0'   # pre-flight #14
    assert "forge_bot_job_mode == 2" in exprs["ForgeBotBreakerTripped"]       # pages only for jobs in apply
    assert all("docs/forgejo.md#forge-bot" in x["annotations"]["summary"] for x in alerts)
    assert "## forge-bot" in (LUMA / "docs/forgejo.md").read_text().splitlines()   # pre-flight #23: the link lands


def _tasks(repo: str) -> list[dict]:
    """Every Actions task (job) of the repo, all pages. Forgejo's repo transfer keeps action_run.owner_id,
    so .../actions/runs hides forge-bot's runs from before its move to realliance-ops (2026-11-04);
    .../actions/tasks selects by repo id and still lists them."""
    out, page = [], 1
    while True:
        r = forge_api("GET", f"/api/v1/repos/{repo}/actions/tasks", params={"page": page, "limit": 50})
        r.raise_for_status()
        batch = r.json()["workflow_runs"]
        out += batch
        if not batch or len(out) >= r.json()["total_count"]:
            return out
        page += 1


def test_pinned_image_is_the_built_release():                     # Success 14 (registry half)
    # The pinned tag's commit was built by CI's image job on a push, and its manifest is the pinned digest.
    # The forge serves manifests from B2 (SERVE_DIRECT), which drops Docker-Content-Digest, so hash the body.
    short, digest = _pinned()
    full = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/git/commits/{short}").json()["sha"]
    assert any(t["head_sha"] == full and t["event"] == "push" and t["name"] == "image" and t["status"] == "success"
               for t in _tasks(FORGE_BOT_REPO))
    m = anonymous_manifest(FORGE_BOT_REPO, f"sha-{short}")
    assert m.status_code == 200 and "sha256:" + hashlib.sha256(m.content).hexdigest() == digest


# --- on galaxy ------------------------------------------------------------------------------------------
@galaxy_only
def test_forge_bot_networkpolicy_selects_live_peers():
    # The policy's peers exist under exactly those labels: Forgejo's API Service selects the pods the
    # Forgejo rule allows, and CoreDNS carries k8s-app=kube-dns.
    egress = _one("NetworkPolicy")["spec"]["egress"]
    svc = json.loads(kube("-n", "forgejo", "get", "svc", "forgejo-http", "-o", "json").stdout)
    assert svc["spec"]["selector"] == egress[1]["to"][0]["podSelector"]["matchLabels"]
    assert [p["port"] for p in svc["spec"]["ports"]] == [3000]
    for ns, sel in (("forgejo", "app.kubernetes.io/name=forgejo,app.kubernetes.io/instance=forgejo"),
                    ("kube-system", "k8s-app=kube-dns")):
        pods = json.loads(kube("-n", ns, "get", "pods", "-l", sel, "-o", "json").stdout)["items"]
        assert pods, f"no pods for {sel} in {ns}"
    eps = json.loads(kube("-n", "forgejo", "get", "endpointslices", "-l", "kubernetes.io/service-name=forgejo-http",
                          "-o", "json").stdout)["items"]
    assert {p["port"] for e in eps for p in e["ports"]} == {3000}   # the pods' port, which the policy names
    # The one ingress peer: Prometheus runs in the namespace the policy names, by its automatic label.
    ns = json.loads(kube("get", "namespace", "prometheus", "-o", "json").stdout)
    assert ns["metadata"]["labels"]["kubernetes.io/metadata.name"] == "prometheus"
    proms = json.loads(kube("-n", "prometheus", "get", "prometheus", "-o", "json").stdout)["items"]
    assert proms and all(p["metadata"]["namespace"] == "prometheus" for p in proms)


@galaxy_only
def test_main_push_builds_and_galaxy_runs_pin():                  # Success 14
    head = forge_api("GET", f"/api/v1/repos/{FORGE_BOT_REPO}/branches/main").json()["commit"]["id"]
    assert any(r["status"] == "success" for r in runs_for(FORGE_BOT_REPO, head))
    _, digest = _pinned()
    pods = json.loads(kube("-n", "forge-bot", "get", "pods", "-l", "app.kubernetes.io/name=forge-bot",
                           "-o", "json").stdout)["items"]
    assert len(pods) == 1, f"{len(pods)} forge-bot pods"
    assert [(o["kind"], o["name"]) for o in pods[0]["metadata"]["ownerReferences"]] == [("StatefulSet", "forge-bot")]
    (status,) = pods[0]["status"]["containerStatuses"]
    assert status["ready"] and status["imageID"].endswith(digest)


@galaxy_only
def test_dry_run_cycle_healthy():
    # Every read completes, every job reports dry-run under its OWN job label (honorLabels), the inventory
    # head is Owner-signed, a cycle completed within two intervals, and nothing critical fires.
    assert {x["metric"]["source"]: x["value"][1] for x in prom_query("forge_bot_read_ok")} == {
        "sso": "1", "forgejo": "1", "inventory": "1"}
    assert {x["metric"]["job"]: x["value"][1] for x in prom_query("forge_bot_job_mode")} == {j: "1" for j in JOBS}
    assert {x["metric"]["check"]: x["value"][1] for x in prom_query("forge_bot_inventory_ok")}.get("signature") == "1"
    (last,) = prom_query("forge_bot_cycle_last_success_timestamp")
    assert time.time() - float(last["value"][1]) < 2 * 330, "no complete cycle in two intervals"
    assert {a: firing(a) for a in CRITICAL} == {a: [] for a in CRITICAL}
