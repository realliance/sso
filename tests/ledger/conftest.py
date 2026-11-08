"""Fixtures for the box's ledger check, host/roles/config_apply/files/sso_ledger.py.

Everything runs offline with real git and GnuPG: throwaway keys, throwaway repos and synthetic people.
No real key, secret or person appears here. The module is loaded from its file and registered as
`sso_ledger`, so tests just `import sso_ledger`.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "host/roles/config_apply/files/sso_ledger.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sso_ledger", SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sso_ledger"] = mod
    spec.loader.exec_module(mod)
    return mod


sso_ledger = _load_module()

GPG = shutil.which("gpg")
# The expired ledger key lives in 2020: made at midnight with a one-day life, it signs at noon.
EXPIRED_BORN = "20200101T000000!"
EXPIRED_SIGNS = "20200101T120000"

SEED_PEOPLE = b"""\
hidden_groups: []
people:
  - username: member-one
    active: true
    groups: [/realliance]
    bootstrap: {email: member-one@example.invalid, first_name: Member, last_name: One}
  - username: member-two
    active: true
    groups: []
    bootstrap: {email: member-two@example.invalid, first_name: Member, last_name: Two}
"""
EMPTY_LEDGER = b"version: 1\nlinks: []\n"


@dataclass(frozen=True)
class Key:
    """A throwaway signing key: its GNUPGHOME, primary fingerprint and the gpg program git signs with."""
    name: str
    home: Path
    fpr: str
    program: str


def _gpg(home: Path, *args: str, faked: str | None = None, data: bytes | None = None) -> bytes:
    cmd = [GPG, "--homedir", str(home), "--batch", "--quiet", "--no-tty", "--pinentry-mode", "loopback",
           "--passphrase", ""]
    if faked:
        cmd += ["--faked-system-time", faked]
    r = subprocess.run(cmd + list(args), input=data, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"gpg {args[0]} failed: {r.stderr.decode(errors='replace')[-500:]}")
    return r.stdout


def _primary_fpr(home: Path) -> str:
    out = _gpg(home, "--list-secret-keys", "--with-colons").decode()
    return next(line.split(":")[9] for line in out.splitlines() if line.startswith("fpr:"))


def _new_home(made: list[Path]) -> Path:
    home = Path(tempfile.mkdtemp(prefix="ledger-gpg-", dir="/tmp"))  # gpg-agent's socket path stays short
    home.chmod(0o700)
    made.append(home)
    return home


def _make_key(name: str, made: list[Path], *, subkey: bool = False, expired: bool = False) -> Key:
    home = _new_home(made)
    uid = f"Test {name} <{name}@example.invalid>"
    if expired:
        _gpg(home, "--quick-gen-key", uid, "ed25519", "sign", "1d", faked=EXPIRED_BORN)
    elif subkey:  # like an operator's key: a certify-only primary with a signing subkey
        _gpg(home, "--quick-gen-key", uid, "ed25519", "cert", "never")
    else:
        _gpg(home, "--quick-gen-key", uid, "ed25519", "sign", "never")
    fpr = _primary_fpr(home)
    if subkey:
        _gpg(home, "--quick-add-key", fpr, "ed25519", "sign", "never")
    program = GPG
    if expired:
        wrapper = home / "gpg-faked"
        wrapper.write_text(f'#!/bin/sh\nexec "{GPG}" --faked-system-time {EXPIRED_SIGNS} "$@"\n')
        wrapper.chmod(0o755)
        program = str(wrapper)
    return Key(name, home, fpr, program)


@pytest.fixture(scope="session")
def keys():
    """operator (signs with a subkey), web-flow (a stand-in in the web-flow class), ledger, untrusted (in no
    class and not in the keyring) and expired (a ledger-class key past its expiry), each in its own GNUPGHOME."""
    made: list[Path] = []
    try:
        yield {
            "operator": _make_key("operator", made, subkey=True),
            "web-flow": _make_key("web-flow", made),
            "ledger": _make_key("ledger", made),
            "untrusted": _make_key("untrusted", made),
            "expired": _make_key("expired", made, expired=True),
        }
    finally:
        for home in made:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, timeout=30)
            shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(scope="session")
def keyring(keys):
    """The verifying keyring, like the box's gnupg-people: public keys only, each with ultimate owner trust.
    The expired key is in it too, so expiry alone is what makes its signatures untrusted."""
    made: list[Path] = []
    home = _new_home(made)
    try:
        for name in ("operator", "web-flow", "ledger", "expired"):
            k = keys[name]
            _gpg(home, "--import", data=_gpg(k.home, "--export", k.fpr))
            _gpg(home, "--import-ownertrust", data=f"{k.fpr}:6:\n".encode())
        yield home
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, timeout=30)
        shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(scope="session")
def trust(keys, tmp_path_factory):
    """people-trust.json's three classes, loaded the way the box loads them."""
    path = tmp_path_factory.mktemp("trust") / "people-trust.json"
    path.write_text(json.dumps({"operators": [keys["operator"].fpr], "web_flow": [keys["web-flow"].fpr],
                                "ledger": [keys["ledger"].fpr, keys["expired"].fpr]}))
    return sso_ledger.load_trust(path)


def git_env(**extra: str) -> dict:
    """A hermetic git environment: no user or system config, synthetic identities, C locale."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", LC_ALL="C",
               GIT_AUTHOR_NAME="Test Author", GIT_AUTHOR_EMAIL="author@example.invalid",
               GIT_COMMITTER_NAME="Test Committer", GIT_COMMITTER_EMAIL="committer@example.invalid")
    env.update(extra)
    return env


@pytest.fixture(autouse=True)
def _hermetic_git(monkeypatch):
    """The module's own git calls inherit os.environ; keep the operator's ~/.gitconfig out of them."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


class PeopleRepo:
    """A throwaway realliance/sso-people: `seed` (operator-signed) holds people.yaml and an empty ledger.yaml.

    commit(changes, signer, parents=..., mode=..., message=...) builds one commit with plumbing, so a test can
    make any shape: `changes` maps a path to its new bytes or None (delete); `signer` is a key name from
    `keys` or None (unsigned); `parents` defaults to [tip] and may be [] (a root) or two (a merge); `mode` is
    one mode for every changed path or a {path: mode} map (a 160000 entry's bytes are the commit it points
    at); `date` sets the author and committer dates; `tree` uses that tree object as is, `changes` ignored.
    Each commit becomes the new tip and main. raw_tree(entries) writes a tree object byte for byte, so a test
    can make one git would never write (duplicate entries)."""

    def __init__(self, path: Path, keys: dict):
        self.path = path
        self.keys = keys
        self.tip: str | None = None
        path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.seed = self.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, "operator",
                                parents=[], message="seed")

    def git(self, *args: str, data: bytes | None = None, **env: str) -> str:
        r = subprocess.run(["git", "-C", str(self.path), *args], input=data, capture_output=True,
                           env=git_env(**env), timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed: {r.stderr.decode(errors='replace')[-500:]}")
        return r.stdout.decode().strip()

    def commit(self, changes: dict[str, bytes | None], signer: str | None, parents: list[str] | None = None,
               mode: str | dict[str, str] = "100644", message: str = "change", date: str | None = None,
               tree: str | None = None) -> str:
        parents = ([self.tip] if self.tip else []) if parents is None else list(parents)
        if tree is None:
            tree = self._tree(changes, parents, mode)
        args = ["commit-tree", tree, "-m", message]
        for p in parents:
            args += ["-p", p]
        env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date} if date else {}
        if signer:
            k = self.keys[signer]
            args = ["-c", f"gpg.program={k.program}", *args, f"-S{k.fpr}"]
            env["GNUPGHOME"] = str(k.home)
        sha = self.git(*args, **env)
        self.git("update-ref", "refs/heads/main", sha)
        self.tip = sha
        return sha

    def _tree(self, changes: dict[str, bytes | None], parents: list[str], mode: str | dict[str, str]) -> str:
        index = self.path / ".git" / "fixture-index"
        index.unlink(missing_ok=True)
        idx = {"GIT_INDEX_FILE": str(index)}
        if parents:
            self.git("read-tree", f"{parents[0]}^{{tree}}", **idx)
        else:
            self.git("read-tree", "--empty", **idx)
        for path, data in changes.items():
            if data is None:
                self.git("update-index", "--force-remove", "--", path, **idx)
                continue
            m = mode.get(path, "100644") if isinstance(mode, dict) else mode
            obj = data.decode().strip() if m == "160000" else self.blob(data)
            self.git("update-index", "--add", "--cacheinfo", f"{m},{obj},{path}", **idx)
        return self.git("write-tree", **idx)

    def is_ancestor(self, a: str, b: str) -> bool:
        r = subprocess.run(["git", "-C", str(self.path), "merge-base", "--is-ancestor", a, b], capture_output=True,
                           env=git_env(), timeout=60)
        if r.returncode not in (0, 1):
            raise RuntimeError("git merge-base failed")
        return r.returncode == 0

    def blob(self, data: bytes) -> str:
        return self.git("hash-object", "-w", "--stdin", data=data)

    def raw_tree(self, entries: list[tuple[str, str, str]]) -> str:
        """A tree object from (mode, name, sha) entries, in the order given, unchecked."""
        raw = b"".join(f"{m} {n}".encode() + b"\0" + bytes.fromhex(s) for m, n, s in entries)
        return self.git("hash-object", "-t", "tree", "--literally", "-w", "--stdin", data=raw)

    def show(self, fmt: str, sha: str, keyring: Path) -> str:
        """One commit's `git log` format fields, verified against `keyring`."""
        return self.git("log", "-1", "--no-show-signature", f"--format={fmt}", sha, GNUPGHOME=str(keyring))


@pytest.fixture
def people_repo(tmp_path, keys):
    return PeopleRepo(tmp_path / "sso-people", keys)
