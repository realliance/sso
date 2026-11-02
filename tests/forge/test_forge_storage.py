"""Forge (project 2) — binaries live in B2 and are served from it; mail goes out through Resend
(spec Success 8; plan Task 4 + Review Focus 4)."""
import hashlib
import os
import secrets
import stat
import subprocess
import time

import requests

from conftest import SECRETS_DIR, _load_env
from forge_helpers import FORGE, b2_names, forge_api, forge_login, forge_token

LFS_SIZE = 120 * 1024 * 1024  # above Cloudflare's 100 MiB proxy limit: git.realliance.net is DNS-only


def _git(cwd, *args, env=None):
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"git {args[0]} failed: {r.stderr[-500:]}"
    return r.stdout


def test_lfs_object_lands_in_b2(forge_user, tmp_path):
    u = forge_user()
    s = forge_login(u)
    repo = f"lfs-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/user/repos", sudo=u.name, json={"name": repo, "private": True}).status_code == 201
    token = forge_token(s, "lfs-test", ["write:repository"])

    askpass = tmp_path / "askpass.sh"   # credentials travel in env, never argv
    askpass.write_text('#!/bin/sh\ncase "$1" in Username*) echo "$FORGE_USER";; *) echo "$FORGE_TOKEN";; esac\n')
    askpass.chmod(stat.S_IRWXU)
    env = dict(os.environ, GIT_ASKPASS=str(askpass), FORGE_USER=u.name, FORGE_TOKEN=token,
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    work = tmp_path / "w"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main", env=env)
    _git(work, "lfs", "install", "--local", env=env)
    _git(work, "lfs", "track", "*.bin", env=env)
    blob = os.urandom(LFS_SIZE)
    (work / "big.bin").write_bytes(blob)
    oid = hashlib.sha256(blob).hexdigest()
    _git(work, "add", ".gitattributes", "big.bin", env=env)
    _git(work, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "lfs", env=env)
    _git(work, "push", "-q", f"{FORGE}/{u.name}/{repo}.git", "main", env=env)

    stored = [f for f in b2_names("realliance-forge-objects", f"lfs/{oid[0:2]}/{oid[2:4]}/{oid[4:]}")]
    assert [f["size"] for f in stored] == [LFS_SIZE]

    batch = requests.post(f"{FORGE}/{u.name}/{repo}.git/info/lfs/objects/batch", auth=(u.name, token), timeout=30,
                          headers={"Accept": "application/vnd.git-lfs+json",
                                   "Content-Type": "application/vnd.git-lfs+json"},
                          json={"operation": "download", "objects": [{"oid": oid, "size": LFS_SIZE}]}).json()
    href = batch["objects"][0]["actions"]["download"]["href"]
    assert href.split("/")[2].endswith("backblazeb2.com")  # SERVE_DIRECT: clients fetch from B2


def test_notification_mail_sent_via_resend(forge_user):
    to = f"delivered+{secrets.token_hex(4)}@resend.dev"  # Resend's test inbox: always delivers
    u = forge_user(email=to)
    forge_login(u)
    repo = f"mail-{secrets.token_hex(3)}"
    assert forge_api("POST", "/api/v1/user/repos", sudo=u.name,
                     json={"name": repo, "private": True, "auto_init": True}).status_code == 201
    assert forge_api("POST", f"/api/v1/repos/{u.name}/{repo}/issues", json={"title": "mail test"}).status_code == 201

    key = _load_env(SECRETS_DIR / "resend/secrets.env")["RESEND_API_KEY"]
    deadline = time.time() + 180
    while time.time() < deadline:
        sent = requests.get("https://api.resend.com/emails", params={"limit": 100}, timeout=20,
                            headers={"Authorization": f"Bearer {key}"}).json().get("data", [])
        if any(to in e.get("to", []) and "git@realliance.net" in e.get("from", "") for e in sent):
            return
        time.sleep(10)
    raise AssertionError("no mail from git@realliance.net reached Resend for the watcher")
