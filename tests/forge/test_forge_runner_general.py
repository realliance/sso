"""Forge CI, general runner: host mode, label `general`, registered for realliance/realliance.net only,
unprivileged, holding no bot or admin secret, with a fresh workspace per job."""
import os
import subprocess

from conftest import SECRETS, _load_env
from forge_helpers import (FORGE_SECRETS, KUBECONFIG, delete_branch, forge_api, galaxy_only,
                           push_probe_workflow, runs_for, wait_for)

SITE_REPO = "realliance/realliance.net"
BOT_REPO = "realliance/forge-bot"
SETTLED = {"success", "failure", "cancelled", "skipped"}
NS = "forgejo-runner-general"

# Same shape as the galaxy runner's probe, minus Go and ko: the general image has neither.
PROBE_SCRIPT = """\
set -eu
test "$(id -u)" = 1000
test ! -e /var/run/docker.sock
test ! -e /var/run/secrets/kubernetes.io
curl --version >/dev/null
unzip -v >/dev/null
node --version
! command -v go
left=$(find /work/act -name 'leftover-*')
test -z "$left"
touch "$GITHUB_WORKSPACE/leftover-$GITHUB_RUN_NUMBER"
"""


def _dump(ns: str, deploy: str) -> str:
    """Every file the pod can read that could hold a credential, as text (undecodable bytes replaced)."""
    r = subprocess.run(["kubectl", "-n", ns, "exec", f"deploy/{deploy}", "--", "sh", "-c",
                        "cat /proc/1/environ; find /etc /work /home -type f -exec cat {} + 2>/dev/null; true"],
                       capture_output=True, timeout=300, env={**os.environ, "KUBECONFIG": KUBECONFIG})
    assert r.returncode == 0, r.stderr[:200]
    return r.stdout.decode("utf-8", "replace")


def _runners(repo: str) -> list[dict]:
    r = forge_api("GET", f"/api/v1/repos/{repo}/actions/runners")
    r.raise_for_status()
    body = r.json()
    return body["runners"] if isinstance(body, dict) else body


def test_general_runner_registered_for_site_only():
    # Instance-scope ephemeral ci-tiny-* runners may appear in a repo listing (cross-plan F15): filter by name.
    site = [r for r in _runners(SITE_REPO) if not r["name"].startswith("ci-tiny-")]
    assert [r["name"] for r in site] == ["general-realliance-net"] or \
        [r["name"] for r in site if r["name"].startswith("general-")] == ["general-realliance-net"]
    general = next(r for r in site if r["name"] == "general-realliance-net")
    assert {l.split(":")[0] for l in general["labels"]} == {"general"}
    assert not any(r["name"] == "galaxy" or r["name"].startswith("galaxy") for r in site)
    bot = _runners(BOT_REPO)
    assert not any(r["name"].startswith("general-") for r in bot)


@galaxy_only
def test_general_runner_holds_no_other_credentials():
    env = _load_env(FORGE_SECRETS)
    values = [env.get("FORGEJO_ADMIN_TOKEN"), env.get("FORGE_BOT_FORGEJO_TOKEN"),
              SECRETS.get("forge_bot_client_secret"), _load_env(FORGE_SECRETS.parent / "runner.env").get("RUNNER_FORGE_BOT_SECRET"),
              env.get("REALLIANCE_NET_REGISTRY_TOKEN")]
    values = [v for v in values if v]
    assert len(values) >= 4, "a canonical secret is missing from sso-secrets"
    # Cross-plan F7: nothing travels into the pod. Dump its files here and search them locally.
    text = _dump(NS, "forgejo-runner-general")
    for control in ("workdir_parent", "HOME=/work/home"):   # present, non-secret: the dump covers what it should
        assert control in text, f"control {control!r} missing from the dump"
    assert _load_env(FORGE_SECRETS.parent / "runner.env")["RUNNER_GENERAL_REALLIANCE_NET_SECRET"] in text   # positive
    for v in values:
        assert v not in text, "a bot/admin secret is readable in the general runner pod"
    # Symmetric: the general secret is not readable in the galaxy runner.
    other = _dump("forgejo-runner", "forgejo-runner")
    assert _load_env(FORGE_SECRETS.parent / "runner.env")["RUNNER_GENERAL_REALLIANCE_NET_SECRET"] not in other


def _settled(repo: str, sha: str):
    statuses = [r["status"] for r in runs_for(repo, sha)]
    return statuses if statuses and set(statuses) <= SETTLED else None


def test_general_probe_job_hardened_and_wiped():
    branch, sha = push_probe_workflow(SITE_REPO, "general", PROBE_SCRIPT)
    try:
        for n in (1, 2):
            assert wait_for(lambda: _settled(SITE_REPO, sha) is not None, timeout=300), f"run {n} never settled"
            assert _settled(SITE_REPO, sha) == ["success"], _settled(SITE_REPO, sha)
            if n == 1:
                branch, sha = push_probe_workflow(SITE_REPO, "general", PROBE_SCRIPT, branch=branch)
    finally:
        delete_branch(SITE_REPO, branch)
