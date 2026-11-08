"""sso-config-apply, the box's apply script (Task 4), end to end with real git, GnuPG and sso-ledger.

Each test builds a box in a temp tree:
- a realliance/sso checkout (SSO_DIR) whose head web-flow's key signed, as Chris's merges are;
- a bare sso-people remote whose history has web-flow commits below the changeover anchor, as the real one does;
  the script clones it into PEOPLE_DIR and fetches it;
- the box's two keyrings (the pull keyring with web-flow, gnupg-people without it), people-trust.json, tofu.env
  and ledger.env, all under SSO_ETC;
- stubs on PATH: `tofu` records each call (its -chdir, the checkout's commit and people.yaml, each var-file's
  guests) and fails a people apply whose var-file names STUB_TOFU_FAIL_IF; `curl` records each status POST.
  SSO_LEDGER_BIN is sso-ledger itself behind a wrapper that can fail (STUB_LEDGER_FAIL) or hang
  (STUB_LEDGER_SLEEP) one command.
Keycloak is a local stub that knows no one. Nothing reaches the network or the box."""
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from .conftest import REPO, SEED_PEOPLE, SRC, PeopleRepo, _gpg, _new_home, git_env, guest_doc, ledger_yaml, link_doc

SCRIPT = REPO / "host/roles/config_apply/files/sso-config-apply.sh"
MODES = ["check", "apply"]
PEOPLE_AT_ANCHOR = SEED_PEOPLE + b"# edited in GitHub's web editor\n"
DROPPED_ENV = ("GIT_", "STUB_", "SSO_", "PEOPLE_", "TF_", "LEDGER_")
PROXIES = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}

TOFU_STUB = r'''#!@PYTHON@ -I
"""tofu stand-in: records each call. `state list` prints the stub's state. A people apply whose var-file names
STUB_TOFU_FAIL_IF fails; with STUB_TOFU_PARTIAL it first records that guest as created, as a half-done apply."""
import json, os, subprocess, sys
log = os.path.join(os.environ["STUB_LOG"], "tofu.jsonl")
state = os.path.join(os.environ["STUB_LOG"], "tofu-state")
args = sys.argv[1:]
chdir = next((a[len("-chdir="):] for a in args if a.startswith("-chdir=")), None)
rest = [a for a in args if not a.startswith("-chdir=")]
cmd = " ".join(rest[:2]) if rest[:1] == ["state"] else (rest[0] if rest else "")
var_files = [a[len("-var-file="):] for a in rest if a.startswith("-var-file=")]
guests = []
for f in var_files:
    with open(f) as fh:
        guests += sorted(json.load(fh)["guests"])
def rev(spec):
    r = subprocess.run(["git", "-C", chdir, "rev-parse", "-q", "--verify", spec], capture_output=True, text=True)
    return r.stdout.strip() or None
rec = {"chdir": chdir, "cmd": cmd, "var_files": var_files, "guests": guests,
       "commit": rev("HEAD") if chdir else None, "people_yaml": rev("HEAD:people.yaml") if chdir else None}
with open(log, "a") as fh:
    fh.write(json.dumps(rec) + "\n")
if cmd == "state list":
    if os.path.exists(state):
        with open(state) as fh:
            sys.stdout.write(fh.read())
    sys.exit(0)
bad = os.environ.get("STUB_TOFU_FAIL_IF")
if cmd == "apply" and bad and bad in guests:
    if os.environ.get("STUB_TOFU_PARTIAL"):
        with open(state, "a") as fh:
            fh.write('keycloak_user.guest["%s"]\n' % bad)
    print("Error: the stub refuses guest %s" % bad, file=sys.stderr)
    sys.exit(1)
'''

CURL_STUB = r'''#!@PYTHON@ -I
"""curl stand-in: records each call's URL, method and body, and where the bearer token came from."""
import json, os, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith("https://"))
headers = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-H"]
if "@-" in headers:
    headers.remove("@-")
    headers += sys.stdin.read().splitlines()
body = args[args.index("-d") + 1] if "-d" in args else None
rec = {"url": url, "method": args[args.index("-X") + 1] if "-X" in args else "GET",
       "body": json.loads(body) if body else None,
       "bearer": any(h.startswith("Authorization: Bearer ") and len(h) > len("Authorization: Bearer ") for h in headers),
       "token_in_argv": any("Authorization" in a for a in args)}
with open(os.path.join(os.environ["STUB_LOG"], "curl.jsonl"), "a") as fh:
    fh.write(json.dumps(rec) + "\n")
sys.exit(22 if os.environ.get("STUB_CURL_FAIL") else 0)
'''

LEDGER_STUB = r'''#!/bin/sh
# sso-ledger as installed, with faults on demand: STUB_LEDGER_FAIL=<command> exits 2 before the tool runs, and
# STUB_LEDGER_SLEEP=<command> hangs for 10 s.
if [ "${STUB_LEDGER_FAIL:-}" = "$1" ]; then echo "sso-ledger $1: failed: injected" >&2; exit 2; fi
if [ "${STUB_LEDGER_SLEEP:-}" = "$1" ]; then exec sleep 10; fi
exec "@PYTHON@" -I "@SRC@" "$@"
'''


class _Keycloak(http.server.BaseHTTPRequestHandler):
    """Keycloak's token endpoint and user queries: a token for anyone, and no user under any name or email."""

    def _send(self, body) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._send({"access_token": "stub-token", "expires_in": 60})

    def do_GET(self):
        self._send([])

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def keycloak():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Keycloak)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def pull_keyring(keys):
    """Like the box's /etc/realliance-sso/gnupg, which only realliance/sso is checked against: the operator's and
    web-flow's keys, ultimately trusted."""
    made: list[Path] = []
    home = _new_home(made)
    try:
        for name in ("operator", "web-flow"):
            k = keys[name]
            _gpg(home, "--import", data=_gpg(k.home, "--export", k.fpr))
            _gpg(home, "--import-ownertrust", data=f"{k.fpr}:6:\n".encode())
        yield home
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, timeout=30)
        shutil.rmtree(home, ignore_errors=True)


class SsoRepo:
    """realliance/sso as ansible-pull leaves it in /var/lib/sso-pull: realm/ at a head web-flow's key signed."""

    def __init__(self, path: Path, keys: dict):
        self.path, self.keys = path, keys
        (path / "realm").mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.commit("first")

    def git(self, *args: str, **env: str) -> str:
        r = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, env=git_env(**env), timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed: {r.stderr.decode(errors='replace')[-500:]}")
        return r.stdout.decode().strip()

    def commit(self, text: str, signer: str | None = "web-flow") -> str:
        (self.path / "realm/main.tf").write_text(f"# {text}\n")
        self.git("add", "-A")
        args, env = ["commit", "-q", "-m", text], {}
        if signer:
            k = self.keys[signer]
            args = ["-c", f"gpg.program={k.program}", *args, f"-S{k.fpr}"]
            env["GNUPGHOME"] = str(k.home)
        self.git(*args, **env)
        return self.git("rev-parse", "HEAD")


@dataclass
class Run:
    rc: int
    out: str
    tofu: list
    posts: list


class Box:
    """One box in a temp tree. `repo` builds sso-people's history and `push` publishes a commit to the remote."""

    def __init__(self, root: Path, mode: str, keys: dict, keyring: Path, pull_keyring: Path, keycloak: str):
        self.root, self.mode, self.keys = root, mode, keys
        self.etc, self.state, self.people_dir = root / "etc", root / "state", root / "sso-people"
        self.log, self.bin = root / "stub-log", root / "stub-bin"
        for d in (self.etc, self.log, self.bin):
            d.mkdir(parents=True)
        self.main, self.drills = self.state / "ledger", self.state / "ledger-drills"
        self.sso = SsoRepo(root / "sso-pull", keys)
        self.remote = root / "sso-people.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], capture_output=True,
                       env=git_env(), timeout=60, check=True)
        # sso-people before the changeover: a web-editor commit and a merge-button merge, both web-flow's. The
        # merge is the head the box last applied, the anchor.
        self.repo = PeopleRepo(root / "people-work", keys)
        pr = self.repo.commit({"notes.md": b"a pr\n"}, "operator")
        edit = self.repo.commit({"people.yaml": PEOPLE_AT_ANCHOR}, "web-flow", parents=[self.repo.seed])
        self.anchor = self.repo.commit({"notes.md": b"a pr\n"}, "web-flow", parents=[edit, pr],
                                       message="Merge pull request #1")
        self.below = [edit, self.anchor]
        self.push(self.anchor)
        (self.etc / "gnupg").symlink_to(pull_keyring)
        (self.etc / "gnupg-people").symlink_to(keyring)
        (self.etc / "people-trust.json").write_text(json.dumps({"operators": [keys["operator"].fpr],
                                                                "ledger": [keys["ledger"].fpr]}))
        (self.etc / "tofu.env").write_text("KEYCLOAK_CLIENT_SECRET=not-a-real-secret\n"
                                           f"TF_VAR_keycloak_url={keycloak}\n"
                                           f"PEOPLE_REPO={self.remote}\n"
                                           "GITHUB_STATUS_TOKEN=not-a-real-token\n")
        (self.etc / "ledger-lookup.secret").write_text("not-a-real-secret\n")
        self.set_env(anchor=self.anchor)
        for name, text in (("tofu", TOFU_STUB), ("curl", CURL_STUB), ("sso-ledger", LEDGER_STUB)):
            path = self.bin / name
            path.write_text(text.replace("@PYTHON@", sys.executable).replace("@SRC@", str(SRC)))
            path.chmod(0o755)

    def set_env(self, anchor: str, mode: str | None = None) -> None:
        """ledger.env as the role renders it."""
        (self.etc / "ledger.env").write_text(f"LEDGER_MODE={mode or self.mode}\nLEDGER_DRILL_REF=ledger-drills\n"
                                             f"PEOPLE_ANCHOR={anchor}\n")

    def push(self, sha: str, branch: str = "main") -> None:
        self.repo.git("push", "-q", "-f", str(self.remote), f"{sha}:refs/heads/{branch}")

    def ledger_commit(self, *links: dict, parents: list[str] | None = None) -> str:
        return self.repo.commit({"ledger.yaml": ledger_yaml(*links)}, "ledger", parents=parents)

    def redeem(self, i: int = 1, username: str = "guest-01") -> str:
        """A pending link, then its redemption: two ledger-key commits, as the service makes them."""
        self.ledger_commit(link_doc(i))
        return self.ledger_commit(link_doc(i, state="redeemed", guest=guest_doc(username)))

    def _calls(self, name: str) -> list:
        path = self.log / f"{name}.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run(self, how: str = "changed", **env: str) -> Run:
        e = {k: v for k, v in os.environ.items()
             if not k.startswith(DROPPED_ENV) and k.lower() not in PROXIES and k not in ("STATE_DIR", "GNUPGHOME")}
        e.update(PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", SSO_DIR=str(self.sso.path),
                 PEOPLE_DIR=str(self.people_dir), STATE_DIR=str(self.state), SSO_ETC=str(self.etc),
                 SSO_LOCK=str(self.root / "lock"), SSO_LEDGER_BIN=str(self.bin / "sso-ledger"),
                 TF_PLUGIN_CACHE_DIR=str(self.root / "plugins"), STUB_LOG=str(self.log),
                 GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", LC_ALL="C")
        e.update(env)
        t0, c0 = len(self._calls("tofu")), len(self._calls("curl"))
        r = subprocess.run(["bash", str(SCRIPT), how], env=e, capture_output=True, text=True, timeout=300)
        return Run(r.returncode, r.stdout + r.stderr, self._calls("tofu")[t0:], self._calls("curl")[c0:])

    def start(self) -> Run:
        """The first run of the new script: sso-people's head is the anchor, which the box already applied."""
        r = self.run()
        assert r.rc == 0, r.out
        return r

    def people_applies(self, r: Run) -> list:
        return [c for c in r.tofu if c["cmd"] == "apply" and c["chdir"] == str(self.people_dir)]

    def people_calls(self, r: Run) -> list:
        return [c for c in r.tofu if c["chdir"] == str(self.people_dir)]

    def realm_applies(self, r: Run) -> list:
        return [c for c in r.tofu if c["cmd"] == "apply" and c["chdir"] == f"{self.sso.path}/realm"]

    def statuses(self, sha: str) -> dict:
        """The latest status the box posted on sso-people commit `sha`, per context: (state, description)."""
        out = {}
        for p in self._calls("curl"):
            if p["url"] == f"https://api.github.com/repos/realliance/sso-people/statuses/{sha}":
                out[p["body"]["context"]] = (p["body"]["state"], p["body"]["description"])
        return out

    def read(self, name: str, where: Path | None = None):
        return json.loads(((where or self.main) / name).read_text())

    def blob(self, sha: str, path: str = "people.yaml") -> str:
        return self.repo.git("rev-parse", f"{sha}:{path}")


@pytest.fixture
def make_box(tmp_path, keys, keyring, pull_keyring, keycloak):
    return lambda mode: Box(tmp_path / f"box-{mode}", mode, keys, keyring, pull_keyring, keycloak)


@pytest.fixture(params=MODES)
def box(request, make_box):
    return make_box(request.param)


@pytest.fixture
def apply_box(make_box):
    return make_box("apply")


@pytest.fixture
def check_box(make_box):
    return make_box("check")


def guests_of(path: Path) -> list:
    return sorted(json.loads(path.read_text())["guests"])


# --- the changeover ------------------------------------------------------------------------------------------

def test_changeover_anchor_seeds_last_good(box):
    """The first run with PEOPLE_ANCHOR at the applied head: last good is the anchor, nothing below it is walked
    (the web-flow history there would freeze), and people.yaml applies at it. The fresh clone checks objects."""
    r = box.start()
    w = box.read("walk.json")
    assert (w["valid"], w["head"], w["last_good"], w["chain"], w["invalid"]) == (True, box.anchor, box.anchor, [], [])
    st = box.read("state.json")
    assert (st["last_good"], st["seen_heads"]) == (box.anchor, [])
    assert [(c["commit"], c["guests"]) for c in box.people_applies(r)] == [(box.anchor, [])]
    assert box.statuses(box.anchor)["sso/apply"][0] == "success"
    assert "ledger-drills" not in r.out                           # no drill branch yet: nothing to say
    git = lambda *a: subprocess.run(["git", "-C", str(box.people_dir), *a], capture_output=True, text=True,
                                    env=git_env()).stdout.strip()
    assert git("config", "fetch.fsckObjects") == "true" and git("rev-parse", "--is-shallow-repository") == "false"


def test_unsigned_sso_head_refused(box):
    """realliance/sso is still checked against the pull keyring, as before."""
    box.sso.commit("unsigned", signer=None)
    r = box.run()
    assert r.rc == 1 and "refusing: realliance/sso HEAD has no trusted signature" in r.out and not r.tofu


# --- apply mode ----------------------------------------------------------------------------------------------

def test_merge_button_commit_freezes_apply_mode(apply_box):
    box = apply_box
    box.start()
    pr = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# a pr\n"}, "operator", parents=[box.anchor])
    m = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# a pr\n"}, "web-flow", parents=[box.anchor, pr],
                        message="Merge pull request #2")
    box.push(m)
    r = box.run()
    assert r.rc == 1 and not box.people_applies(r)
    state, text = box.statuses(m)["sso/apply"]
    assert state == "failure" and text.startswith(f"frozen: invalid:untrusted-signer@{m[:7]}"), text


def test_apply_mode_freeze_applies_nothing(apply_box):
    """An invalid commit under a valid head: no people tofu call at all, last good included."""
    box = apply_box
    box.start()
    w = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web editor\n"}, "web-flow")
    o = box.repo.commit({"notes.md": b"on top\n"}, "operator")
    box.push(o)
    r = box.run()
    assert r.rc == 1, r.out
    assert box.people_calls(r) == []
    state, text = box.statuses(o)["sso/apply"]
    assert state == "failure" and text.startswith(f"frozen: invalid:untrusted-signer@{w[:7]}"), text
    assert box.statuses(o)["sso/ledger"][0] == "pending"


def test_seen_head_freeze_is_sticky(apply_box):
    """A stale operator commit force-pushed to main, then merged back on a second parent (the Update-branch
    family): the seen head left the line, so the box freezes, and a later valid push stays frozen."""
    box = apply_box
    box.start()
    lg = box.ledger_commit(link_doc(1))
    box.push(lg)
    assert box.run().rc == 0 and box.read("state.json")["last_good"] == lg
    q = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# stale\n"}, "operator", parents=[box.anchor])
    box.push(q)
    r = box.run()
    assert r.rc == 1 and box.read("walk.json")["reason"] == "not-fast-forward"
    p = box.repo.commit({"notes.md": b"next\n"}, "operator", parents=[lg])
    m = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# stale\n"}, "operator", parents=[p, q])
    box.push(m)
    r = box.run()
    assert r.rc == 1 and box.read("walk.json")["reason"] == f"not-first-parent-descendant@{q[:7]}"
    k = box.ledger_commit(link_doc(1), link_doc(2))
    box.push(k)
    r = box.run()
    assert r.rc == 1 and not box.people_applies(r)
    assert box.read("state.json")["seen_heads"] == [q, m, k]
    assert box.statuses(k)["sso/apply"] == (
        "failure", f"frozen: not-first-parent-descendant@{q[:7]}; seen: {q[:7]},{m[:7]},{k[:7]}")


def test_apply_mode_recovery_resumes(apply_box):
    box = apply_box
    box.start()
    w = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web editor\n"}, "web-flow")
    box.push(w)
    assert box.run().rc == 1
    rec = box.repo.commit({"people.yaml": PEOPLE_AT_ANCHOR}, "operator",
                          message=f"Revert the web edit\n\nReviewed-Range: {box.anchor}..{w}\n")
    box.push(rec)
    r = box.run()
    assert r.rc == 0, r.out
    assert [c["commit"] for c in box.people_applies(r)] == [rec]
    st = box.read("state.json")
    assert (st["last_good"], st["seen_heads"]) == (rec, [])
    assert box.statuses(rec)["sso/apply"][0] == "success"


def test_apply_mode_hands_admitted_guest(apply_box):
    box = apply_box
    box.start()
    head = box.redeem(1, "guest-01")
    box.push(head)
    r = box.run()
    assert r.rc == 0, r.out
    assert [(c["commit"], c["guests"]) for c in box.people_applies(r)] == [(head, ["guest-01"])]
    assert box.read("state.json")["admitted"]["guest-01"]["link"] == "l-0000000000000001"
    assert guests_of(box.main / "handed.json") == ["guest-01"]
    assert box.statuses(head)["sso/apply"] == ("success", "applied: 1 admitted, 0 refused, 0 deferred")


def test_apply_mode_refused_ledger_still_applies_people(apply_box):
    """A ledger-key commit that adds a `groups` key: path-valid, so no freeze; the ledger is refused, and
    people.yaml applies at the head with the guests handed before."""
    box = apply_box
    box.start()
    box.push(box.redeem(1, "guest-01"))
    assert box.run().rc == 0
    doc = {"version": 1, "links": [link_doc(1, state="redeemed", guest=guest_doc("guest-01"))],
           "groups": ["/realliance"]}
    bad = box.repo.commit({"ledger.yaml": yaml.safe_dump(doc, sort_keys=False).encode()}, "ledger")
    box.push(bad)
    r = box.run()
    assert r.rc == 0, r.out
    statuses = box.statuses(bad)
    assert statuses["sso/apply"][0] == "success"
    assert statuses["sso/ledger"][0] == "failure" and statuses["sso/ledger"][1].startswith("ledger refused: schema:")
    assert [(c["commit"], c["guests"]) for c in box.people_applies(r)] == [(bad, ["guest-01"])]


def test_new_guest_apply_failure_retries_without_it(apply_box):
    box = apply_box
    box.start()
    head = box.redeem(1, "bad-guest")
    box.push(head)
    r = box.run(STUB_TOFU_FAIL_IF="bad-guest")
    assert r.rc == 0, r.out
    assert [c["guests"] for c in box.people_applies(r)] == [["bad-guest"], []]
    st = box.read("state.json")
    assert "bad-guest" not in st["admitted"] and st["refused"]["l-0000000000000001"]["reason"] == "apply-failed"
    assert guests_of(box.main / "handed.json") == []
    assert box.statuses(head)["sso/apply"][0] == "success"
    # The set that applied is the one the next run hands: nothing new, so nothing runs.
    r = box.run(STUB_TOFU_FAIL_IF="bad-guest")
    assert r.rc == 0 and not box.people_applies(r)


def test_partial_create_skips_the_retry(apply_box):
    """A failed apply that left the new guest in tofu's state: a retry without the guest would destroy what was
    made (or trip prevent_destroy), so the run fails instead, and the guest stays admitted."""
    box = apply_box
    box.start()
    head = box.redeem(1, "bad-guest")
    box.push(head)
    r = box.run(STUB_TOFU_FAIL_IF="bad-guest", STUB_TOFU_PARTIAL="1")
    assert r.rc == 1, r.out
    assert [c["guests"] for c in box.people_applies(r)] == [["bad-guest"]]
    st = box.read("state.json")
    assert "bad-guest" in st["admitted"] and not st["refused"]
    assert box.statuses(head)["sso/apply"] == ("failure", "people apply failed")


def test_rebuild_seeds_from_recorded_anchor(apply_box):
    """A rebuilt box (no state at all) starts from people_anchor_commit and nothing else: never a later operator
    commit. After a recovery the anchor must be bumped, or the box freezes until a new recovery."""
    box = apply_box
    box.start()
    v = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# v\n"}, "operator")
    box.push(v)
    assert box.run().rc == 0
    w = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web editor\n"}, "web-flow")
    box.push(w)
    assert box.run().rc == 1
    rec = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# v\n"}, "operator",
                          message=f"Revert\n\nReviewed-Range: {v}..{w}\n")
    box.push(rec)
    assert box.run().rc == 0 and box.read("state.json")["last_good"] == rec
    shutil.rmtree(box.state)                                      # the rebuild: the anchor was never bumped
    r = box.run()
    assert r.rc == 1 and not box.people_applies(r)
    st = box.read("state.json")
    assert (st["last_good"], st["seen_heads"]) == (box.anchor, [rec])
    assert box.statuses(rec)["sso/apply"][1].startswith(f"frozen: recovery-stale-last-good@{rec[:7]}")
    box.set_env(anchor=rec)                                       # an operator bumps people_anchor_commit
    shutil.rmtree(box.state)
    r = box.run()
    assert r.rc == 0, r.out
    st = box.read("state.json")
    assert (st["last_good"], st["seen_heads"]) == (rec, [])
    assert [c["commit"] for c in box.people_applies(r)] == [rec]


# --- check mode ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("below", ["last-good", "operator"])
def test_check_mode_applies_last_good_or_operator_below_a_web_flow_head(below, check_box):
    box = check_box
    box.start()
    want = box.anchor
    if below == "operator":
        want = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    w = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web editor\n"}, "web-flow")
    box.push(w)
    r = box.run()
    assert r.rc == 0, r.out
    assert [c["commit"] for c in box.people_applies(r)] == [want]
    state, text = box.statuses(w)["sso/apply"]
    assert state == "failure" and text.startswith(f"check: would be frozen: invalid:untrusted-signer@{w[:7]}"), text


def test_check_mode_service_push_at_head_does_not_block(check_box):
    """A ledger-key head over an operator commit: the head walks valid, so check mode applies there, and the
    people.yaml it applies is the operator commit's. The ledger key isn't in the pull keyring: that no longer
    matters on sso-people."""
    box = check_box
    box.start()
    o = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    k = box.ledger_commit(link_doc(1))
    box.push(k)
    r = box.run()
    assert r.rc == 0, r.out
    [apply] = box.people_applies(r)
    assert apply["people_yaml"] == box.blob(o) and apply["commit"] == box.read("walk.json")["newest_trusted"] == k
    state, text = box.statuses(k)["sso/apply"]
    assert state == "success" and text.startswith("check: would be applied"), text


def test_check_mode_logs_a_freeze_and_still_applies(check_box):
    box = check_box
    box.start()
    o = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# ledger key\n", "ledger.yaml": ledger_yaml(link_doc(1))},
                          "ledger")
    box.push(bad)
    r = box.run()
    assert r.rc == 0, r.out
    assert [c["commit"] for c in box.people_applies(r)] == [o]
    assert f"frozen: invalid:ledger-path@{bad[:7]}" in r.out
    state, text = box.statuses(bad)["sso/apply"]
    assert state == "failure" and text.startswith(f"check: would be frozen: invalid:ledger-path@{bad[:7]}"), text
    assert box.statuses(bad)["sso/ledger"][0] == "pending"


def test_walk_crash_does_not_block_check(check_box):
    """bash applies the stored last good: never the new head, never a commit it worked out itself."""
    box = check_box
    box.start()
    o = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    box.push(o)
    r = box.run(STUB_LEDGER_FAIL="walk")
    assert r.rc == 0, r.out
    assert [c["commit"] for c in box.people_applies(r)] == [box.anchor]
    assert box.statuses(o)["sso/apply"] == ("failure", "check: walk failed")
    r = box.run()
    assert r.rc == 0 and [c["commit"] for c in box.people_applies(r)] == [o]


# --- failures in the ledger path -----------------------------------------------------------------------------

@pytest.mark.parametrize("fault", ["crash", "timeout"])
def test_walk_crash_fails_closed_in_apply_and_keeps_state(fault, apply_box):
    box = apply_box
    box.start()
    before = (box.main / "state.json").read_bytes()
    assert (box.main / "walk.json").exists()                      # the last run's, stale from here on
    o = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    box.push(o)
    env = {"STUB_LEDGER_FAIL": "walk"} if fault == "crash" else {"STUB_LEDGER_SLEEP": "walk",
                                                                  "SSO_LEDGER_TIMEOUT": "2"}
    r = box.run(**env)
    assert r.rc == 1, r.out
    assert box.people_calls(r) == []
    assert box.statuses(o)["sso/apply"] == ("failure", "walk failed")
    assert (box.main / "state.json").read_bytes() == before and not (box.main / "walk.json").exists()


def _content_fails(box, **env):
    """A content step that fails never blocks: people.yaml applies at the walked commit with the last handed
    guests (in apply mode a guest admitted earlier, so the set isn't empty), and sso/ledger fails."""
    box.start()
    if box.mode == "apply":
        box.push(box.redeem(1, "guest-01"))
        assert box.run().rc == 0
    handed = guests_of(box.main / "handed.json")
    assert handed == (["guest-01"] if box.mode == "apply" else [])
    o = box.repo.commit({"notes.md": b"next\n"}, "operator")
    box.push(o)
    r = box.run(**env)
    assert r.rc == 0, r.out
    assert "ledger: content failed; people apply continues with the last handed guests" in r.out
    assert [(c["commit"], c["guests"]) for c in box.people_applies(r)] == [(o, handed)]
    state, text = box.statuses(o)["sso/ledger"]
    assert state == "failure" and text.endswith("content failed"), text
    assert box.statuses(o)["sso/apply"][0] == "success"


def test_content_crash_never_blocks(box):
    _content_fails(box, STUB_LEDGER_FAIL="content")


def test_content_timeout_never_blocks(box):
    _content_fails(box, STUB_LEDGER_SLEEP="content", SSO_LEDGER_TIMEOUT="2")


# --- the drill ref, changed mode, statuses and test branches ----------------------------------------------------

def test_drill_ref_never_applied(box):
    box.start()
    main_before = box.read("state.json")
    box.ledger_commit(link_doc(1), parents=[box.anchor])
    drill = box.ledger_commit(link_doc(1, state="redeemed", guest=guest_doc("drill-guest")))
    box.push(drill, "ledger-drills")
    r = box.run()
    assert r.rc == 0, r.out
    assert not any("drill-guest" in c["guests"] for c in r.tofu) and not box.people_applies(r)
    assert json.loads((box.main / "guests.next.json").read_text()) == {"guests": {}}
    assert guests_of(box.main / "handed.json") == []
    w = box.read("walk.json", box.drills)
    assert (w["valid"], w["dry"], w["apply_commit"]) == (True, True, None)
    assert box.read("content.json", box.drills)["would_admit"] == ["drill-guest"]
    assert set(box.statuses(drill)) == {"sso/apply", "sso/ledger"}
    main_after = box.read("state.json")
    assert {k: main_after[k] for k in ("last_good", "seen_heads", "admitted")} == \
           {k: main_before[k] for k in ("last_good", "seen_heads", "admitted")}
    # A frozen drill head: its own seen-heads list grows, main's doesn't, and main still applies.
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web editor\n"}, "web-flow", parents=[drill])
    box.push(bad, "ledger-drills")
    r = box.run()
    assert r.rc == 0, r.out
    assert box.read("state.json", box.drills)["seen_heads"] == [bad]
    assert box.read("state.json")["seen_heads"] == []
    assert f"invalid:untrusted-signer@{bad[:7]}" in box.statuses(bad)["sso/apply"][1]
    # The drill branch deleted: no drill check, no status, and nothing logged about it.
    box.repo.git("push", "-q", str(box.remote), ":refs/heads/ledger-drills")
    r = box.run()
    assert r.rc == 0 and r.posts == [] and "ledger-drills" not in r.out, r.out


def test_changed_mode_skips_realm_when_sso_unchanged(box):
    r = box.start()
    assert box.realm_applies(r) and box.people_applies(r)
    o = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    box.push(o)
    r = box.run()
    assert [c["commit"] for c in box.people_applies(r)] == [o] and not box.realm_applies(r)
    r = box.run()
    assert r.rc == 0 and not [c for c in r.tofu if c["cmd"] == "apply"]
    box.sso.commit("a realm change")
    r = box.run()
    assert box.realm_applies(r)
    r = box.run("force")
    assert box.realm_applies(r) and box.people_applies(r)


def test_statuses_posted_once_per_verdict(box):
    first = box.start()
    again, forced = box.run(), box.run("force")
    assert again.rc == forced.rc == 0
    people = [p for p in first.posts if "/sso-people/" in p["url"]]
    assert sorted(p["body"]["context"] for p in people) == ["sso/apply", "sso/ledger"]
    assert {p["url"] for p in people} == {f"https://api.github.com/repos/realliance/sso-people/statuses/{box.anchor}"}
    assert all(p["method"] == "POST" and p["bearer"] and not p["token_in_argv"] for p in first.posts)
    assert again.posts == [] and forced.posts == []


def test_unsigned_people_head_never_applied(box):
    """PEOPLE_REF=<test branch>, as the live test runs it: check applies the commit below and exits 0, apply
    freezes and exits 1. The branch runs in throwaway ledger state: main's is never touched."""
    box.start()
    before = (box.main / "state.json").read_bytes()
    u = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# unsigned\n"}, None, parents=[box.anchor])
    box.push(u, "apply-test-unsigned")
    r = box.run("force", PEOPLE_REF="apply-test-unsigned")
    if box.mode == "check":
        assert r.rc == 0, r.out
        assert [c["commit"] for c in box.people_applies(r)] == [box.anchor]
    else:
        assert r.rc == 1, r.out
        assert box.people_calls(r) == []
    state, text = box.statuses(u)["sso/apply"]
    assert state == "failure" and f"frozen: invalid:unsigned@{u[:7]}" in text, text
    assert (box.main / "state.json").read_bytes() == before
    assert sorted(p.name for p in box.state.iterdir() if p.name.startswith("ledger")) == ["ledger"]
    # main's next run: where the test branch applied something, main applies its own commit again.
    r = box.run()
    assert r.rc == 0, r.out
    assert [c["commit"] for c in box.people_applies(r)] == ([box.anchor] if box.mode == "check" else [])


def test_test_branch_never_hands_its_own_guests(apply_box):
    """A valid test branch with a redemption, in apply mode: people.yaml applies at its head with main's last
    handed guests, and the guest it would admit reaches neither tofu nor main's state."""
    box = apply_box
    box.start()
    head = box.redeem(1, "branch-guest")
    box.push(head, "apply-test-guest")
    r = box.run("force", PEOPLE_REF="apply-test-guest")
    assert r.rc == 0, r.out
    assert [(c["commit"], c["guests"]) for c in box.people_applies(r)] == [(head, [])]
    assert "branch-guest" not in box.read("state.json")["admitted"]
    assert guests_of(box.main / "handed.json") == []
