"""Forge (project 2) — git over SSH on port 22 from the internet and the LAN, while the router's own
SSH stays reachable on the LAN and the tailnet (spec Success 7, amended)."""
import secrets
import subprocess

import pytest

from forge_helpers import FORGE_LB, VPS, WAN_IP, forge_api, forge_login, lan_only, ssh_keyscan

ROUTER_LAN, ROUTER_TAILNET = "192.168.0.1", "100.96.171.43"


@pytest.fixture(scope="module")
def forgejo_key():
    key = ssh_keyscan(FORGE_LB)
    assert key, "Forgejo's SSH service at the MetalLB IP did not answer"
    return key


@lan_only
def test_wan_ssh_reaches_forgejo(forgejo_key):
    assert ssh_keyscan("git.realliance.net", via=VPS) == forgejo_key


@lan_only
def test_lan_ssh_to_wan_ip_reaches_forgejo(forgejo_key):
    assert ssh_keyscan(WAN_IP) == forgejo_key


@lan_only
def test_router_ssh_on_lan_and_tailnet_is_vyos(forgejo_key):
    for host in (ROUTER_LAN, ROUTER_TAILNET):
        key = ssh_keyscan(host)
        assert key and key != forgejo_key, host


@lan_only
def test_github_ssh_unaffected(forgejo_key):
    assert ssh_keyscan("github.com") not in ("", forgejo_key)


def _vps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", "-o", "BatchMode=yes", VPS, "bash", "-s"], input=script,
                          capture_output=True, text=True, timeout=120)


def test_clone_over_ssh_from_internet(forge_user):
    u = forge_user()
    forge_login(u)
    repo = f"ssh-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/user/repos", sudo=u.name,
                     json={"name": repo, "private": True, "auto_init": True}).status_code == 201
    tmp = f"/tmp/forge-ssh-test-{secrets.token_hex(4)}"
    try:
        made = _vps(f"set -e; umask 077; mkdir {tmp}; ssh-keygen -q -t ed25519 -N '' -C forge-test -f {tmp}/k; cat {tmp}/k.pub")
        assert made.returncode == 0, made.stderr
        added = forge_api("POST", f"/api/v1/admin/users/{u.name}/keys", json={"title": "test", "key": made.stdout.strip()})
        assert added.status_code == 201, added.text
        ls = _vps(f"GIT_SSH_COMMAND='ssh -i {tmp}/k -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
                  f"-o UserKnownHostsFile={tmp}/kh' git ls-remote git@git.realliance.net:{u.name}/{repo}.git")
        assert ls.returncode == 0 and "refs/heads/main" in ls.stdout, ls.stderr[-300:]
    finally:
        _vps(f"rm -rf {tmp}")
