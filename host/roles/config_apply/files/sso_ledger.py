#!/opt/ansible/bin/python3 -I
"""sso-ledger: the box's check of ledger.yaml in realliance/sso-people.

Managed by realliance/sso (host/roles/config_apply), installed as /usr/local/sbin/sso-ledger. It runs in the
pull role's Python 3.12 venv, whose PyYAML ansible-core already needs, and stays 3.12 compatible.

The invite service writes ledger.yaml with its own key. This code is what keeps that key harmless: a commit
signed with it may change ledger.yaml alone, and the file it writes must parse strictly and change only in
the ways the ledger key may change it. On sso-people only operator keys and that ledger key are trusted: GitHub's
web-flow key signs every web-editor commit for anyone, in any repo, so a web-flow commit there is invalid like an
unsigned one, merge-button merges included. Errors name codes, keys, link ids and lines, never a value from the
file, because a value may be an email or a name.

The command line (main) is what sso-config-apply runs, one flock, each run:

    sso-ledger walk     the commit check (walk), git and signatures only; stores last good and the seen heads
    sso-ledger content  the ledger's content (check_ledger) and who becomes a guest (admit); writes the var-file
    sso-ledger settle   after the people apply: --applied, or --failed-new when only the previous set applied
    sso-ledger seed | forget | fallback   a rebuilt box, an erasure, a content step that failed

State lives in one directory (/var/lib/sso-config-apply/ledger, no backup), every file 0600 and replaced
atomically. Every output but the var-file holds ids only: shas, link ids, usernames and codes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Mapping, Protocol, runtime_checkable

import yaml

MAX_LEDGER_BYTES = 1_048_576
MAX_EXPIRY = timedelta(days=7)
STATES = ("pending", "redeemed", "revoked")
MFA = ("webauthn", "totp")

_ID = re.compile(r"l-[0-9a-f]{16}")
_TOKEN_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SHOWN_KEY = re.compile(r"[a-z_]{1,32}")


class SchemaError(Exception):
    """ledger.yaml is not a ledger: refused before anything reads its content."""
    CODES = frozenset({"too-large", "yaml", "duplicate-key", "alias", "unknown-key", "missing-key", "type",
                       "value"})

    def __init__(self, code: str, detail: str = ""):
        if code not in self.CODES:
            raise ValueError(f"unknown schema code {code}")
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class TransitionError(Exception):
    """A change to ledger.yaml that the ledger key may not sign."""
    CODES = frozenset({"immutable", "removal", "reactivate", "not-allowed", "version"})

    def __init__(self, code: str, link_id: str | None, detail: str = ""):
        if code not in self.CODES:
            raise ValueError(f"unknown transition code {code}")
        where = f" link {link_id}" if link_id else ""
        super().__init__(f"{code}:{where}" + (f" {detail}" if detail else ""))
        self.code = code
        self.link_id = link_id
        self.detail = detail


@dataclass(frozen=True)
class Bootstrap:
    email: str
    first_name: str
    last_name: str | None


@dataclass(frozen=True)
class Guest:
    username: str
    bootstrap: Bootstrap
    mfa: str
    active: bool


@dataclass(frozen=True)
class Link:
    id: str
    inviter: str
    created: str
    expires: str
    token_sha256: str
    state: str
    redeemed: str | None
    revoked: str | None
    guest: Guest | None


@dataclass(frozen=True)
class Ledger:
    version: int
    links: tuple[Link, ...]


# --- the loader ----------------------------------------------------------------------------------------------
#
# Plain (unquoted) scalars resolve only to what reads the same in YAML 1.1 and 1.2: true/false, null, decimal
# integers of at most 18 digits and strings. A plain scalar that either version reads as another type (a
# timestamp, yes/no/on/off, an octal, base-60 or float number, a longer integer, a merge key) is refused as
# `type`: the writer quotes such strings, and a reader never has to guess. No default resolver survives, so no
# datetime is ever built, int() never sees Python's 4300-digit limit, and every accepted timestamp is a quoted
# string the schema checks.

_AMBIGUOUS_TAG = "tag:realliance.net,2026:ambiguous"
_AMBIGUOUS = re.compile(r"""^(?:
      y|Y|yes|Yes|YES|n|N|no|No|NO|on|On|ON|off|Off|OFF
    | [-+]?(?:0b[01_]+|0o[0-7_]+|0x[0-9a-fA-F_]+)
    | [-+]?(?:[0-9][0-9_:]*(?:\.[0-9_]*)?|\.[0-9_]+)(?:[eE][-+]?[0-9]+)?
    | [-+]?\.(?:inf|Inf|INF) | \.(?:nan|NaN|NAN)
    | [0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?
    | <<|=
)$""", re.X)


class _Loader(yaml.SafeLoader):
    yaml_implicit_resolvers: dict = {}

    def compose_node(self, parent, index):
        event = self.peek_event()
        line = event.start_mark.line + 1
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise SchemaError("alias", f"anchor or alias at line {line}")
        if getattr(event, "tag", None) is not None:
            raise SchemaError("yaml", f"explicit tag at line {line}")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                if type(key) is not str:
                    raise SchemaError("type", f"a key that is not a string at line {key_node.start_mark.line + 1}")
                if key in seen:
                    raise SchemaError("duplicate-key", f"key {_show(key)} twice at line {key_node.start_mark.line + 1}")
                seen.add(key)
        return super().construct_mapping(node, deep=deep)

    def construct_ambiguous(self, node):
        raise SchemaError("type", f"unquoted scalar that YAML may read as a non-string at line "
                                  f"{node.start_mark.line + 1}; quote it")


_Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
                              list("tTfF"))
_Loader.add_implicit_resolver("tag:yaml.org,2002:null", re.compile(r"^(?:~|null|Null|NULL|)$"),
                              ["~", "n", "N", ""])
_Loader.add_implicit_resolver("tag:yaml.org,2002:int", re.compile(r"^-?(?:0|[1-9][0-9]{0,17})$"),
                              list("-0123456789"))
_Loader.add_implicit_resolver(_AMBIGUOUS_TAG, _AMBIGUOUS, list("yYnNoO+-.0123456789<="))
_Loader.add_constructor(_AMBIGUOUS_TAG, _Loader.construct_ambiguous)


def _show(key: str) -> str:
    return key if _SHOWN_KEY.fullmatch(key) else "(not shown)"


def _load(data: bytes):
    loader = None
    try:
        loader = _Loader(data)            # the reader starts decoding here
        return loader.get_single_data()
    except SchemaError:
        raise
    except yaml.MarkedYAMLError as e:      # its own text quotes the file, so only the line is kept
        mark = e.problem_mark or e.context_mark
        raise SchemaError("yaml", f"not valid YAML at line {mark.line + 1}" if mark else "not valid YAML") from None
    except yaml.YAMLError:
        raise SchemaError("yaml", "not valid YAML") from None
    except RecursionError:
        raise SchemaError("yaml", "nested too deeply") from None
    finally:
        if loader is not None:
            loader.dispose()


# --- the schema ----------------------------------------------------------------------------------------------

_TOP = ({"version", "links"}, set())
_LINK = ({"id", "inviter", "created", "expires", "token_sha256", "state"}, {"redeemed", "revoked", "guest"})
_GUEST = ({"username", "bootstrap", "mfa", "active"}, set())
_BOOTSTRAP = ({"email", "first_name"}, {"last_name"})


def _mapping(m, spec, where: str) -> dict:
    if type(m) is not dict:
        raise SchemaError("type", f"{where} must be a mapping")
    required, optional = spec
    unknown = [k for k in m if k not in required and k not in optional]
    if unknown:
        raise SchemaError("unknown-key", f"{where}: unknown key {_show(unknown[0])}")
    missing = sorted(required - m.keys())
    if missing:
        raise SchemaError("missing-key", f"{where}: missing {missing[0]}")
    return m


def _str(m: dict, key: str, where: str) -> str:
    if type(m[key]) is not str:
        raise SchemaError("type", f"{where}.{key} must be a string")
    return m[key]


def _time(m: dict, key: str, where: str) -> str:
    value = _str(m, key, where)
    if not _TIME.fullmatch(value):
        raise SchemaError("value", f"{where}.{key} must be a 'YYYY-MM-DDTHH:MM:SSZ' time")
    try:
        parse_time(value)
    except ValueError:
        raise SchemaError("value", f"{where}.{key} is not a real time") from None
    return value


def parse_time(value: str) -> datetime:
    """A ledger time ('YYYY-MM-DDTHH:MM:SSZ') as an aware UTC datetime."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _guest(m, where: str) -> Guest:
    _mapping(m, _GUEST, where)
    username = _str(m, "username", where)
    b = _mapping(m["bootstrap"], _BOOTSTRAP, f"{where}.bootstrap")
    bootstrap = Bootstrap(_str(b, "email", f"{where}.bootstrap"), _str(b, "first_name", f"{where}.bootstrap"),
                          _str(b, "last_name", f"{where}.bootstrap") if "last_name" in b else None)
    mfa = _str(m, "mfa", where)
    if mfa not in MFA:
        raise SchemaError("value", f"{where}.mfa must be one of {', '.join(MFA)}")
    if type(m["active"]) is not bool:
        raise SchemaError("type", f"{where}.active must be true or false")
    return Guest(username, bootstrap, mfa, m["active"])


def _link(m, where: str) -> Link:
    _mapping(m, _LINK, where)
    link_id = _str(m, "id", where)
    if not _ID.fullmatch(link_id):
        raise SchemaError("value", f"{where}.id must be l- and 16 lowercase hex")
    where = f"link {link_id}"
    inviter = _str(m, "inviter", where)
    created, expires = _time(m, "created", where), _time(m, "expires", where)
    try:
        latest = parse_time(created) + MAX_EXPIRY
    except OverflowError:                 # within 7 days of datetime's year-9999 limit
        raise SchemaError("value", f"{where}: created is too late") from None
    if not parse_time(created) < parse_time(expires) <= latest:
        raise SchemaError("value", f"{where}: expires must be after created and at most 7 days later")
    token = _str(m, "token_sha256", where)
    if not _TOKEN_SHA256.fullmatch(token):
        raise SchemaError("value", f"{where}.token_sha256 must be 64 lowercase hex")
    state = _str(m, "state", where)
    if state not in STATES:
        raise SchemaError("value", f"{where}.state must be one of {', '.join(STATES)}")
    redeemed = _time(m, "redeemed", where) if "redeemed" in m else None
    revoked = _time(m, "revoked", where) if "revoked" in m else None
    guest = _guest(m["guest"], f"{where}.guest") if "guest" in m else None
    for key, present, wanted in (("redeemed", redeemed is not None, state == "redeemed"),
                                 ("revoked", revoked is not None, state == "revoked"),
                                 ("guest", guest is not None, state == "redeemed")):
        if present != wanted:
            raise SchemaError("value", f"{where}: {key} is {'set' if present else 'missing'} on a {state} link")
    return Link(link_id, inviter, created, expires, token, state, redeemed, revoked, guest)


def parse_ledger(data: bytes) -> Ledger:
    """Parse ledger.yaml strictly, or raise SchemaError. The size check runs before any parsing."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("parse_ledger takes bytes")
    if len(data) > MAX_LEDGER_BYTES:
        raise SchemaError("too-large", f"{len(data)} bytes, at most {MAX_LEDGER_BYTES}")
    doc = _mapping(_load(bytes(data)), _TOP, "the ledger")
    if type(doc["version"]) is not int:
        raise SchemaError("type", "version must be an integer")
    if doc["version"] != 1:
        raise SchemaError("value", "version must be 1")
    if type(doc["links"]) is not list:
        raise SchemaError("type", "links must be a list")
    links, seen = [], set()
    for i, m in enumerate(doc["links"]):
        link = _link(m, f"links[{i}]")
        if link.id in seen:
            raise SchemaError("value", f"link {link.id} appears twice")
        seen.add(link.id)
        links.append(link)
    return Ledger(doc["version"], tuple(links))


# --- the ledger key's rights ---------------------------------------------------------------------------------

_LINK_IMMUTABLE = ("inviter", "created", "expires", "token_sha256")


def _by_id(ledger: Ledger) -> dict[str, Link]:
    out: dict[str, Link] = {}
    for link in ledger.links:
        if link.id in out:
            raise TransitionError("not-allowed", link.id, "appears twice")
        out[link.id] = link
    return out


def _check_link(old: Link, new: Link) -> None:
    for field in _LINK_IMMUTABLE:
        if getattr(old, field) != getattr(new, field):
            raise TransitionError("immutable", old.id, field)
    if old.state == "pending":
        if new.state == "pending" and new != old:
            raise TransitionError("immutable", old.id, "a pending link changed")
        if new.state == "redeemed" and (new.guest is None or not new.guest.active):
            raise TransitionError("not-allowed", old.id, "redeemed without an active guest")
        return
    if new.state != old.state:
        raise TransitionError("not-allowed", old.id, f"{old.state} to {new.state}")
    if old.state == "revoked":
        if new != old:
            raise TransitionError("immutable", old.id, "revoked")
        return
    if new.redeemed != old.redeemed:
        raise TransitionError("immutable", old.id, "redeemed")
    og, ng = old.guest, new.guest
    if og is None or ng is None:
        raise TransitionError("not-allowed", old.id, "redeemed without a guest")
    for field in ("username", "bootstrap", "mfa"):
        if getattr(og, field) != getattr(ng, field):
            raise TransitionError("immutable", old.id, f"guest.{field}")
    if not og.active and ng.active:
        raise TransitionError("reactivate", old.id)


def check_transition(before: Ledger, after: Ledger) -> None:
    """Raise TransitionError unless the ledger key may change `before` into `after`: add a pending link, move
    pending to revoked or to redeemed with an active guest, and set guest.active from true to false. Links
    are matched by id; their order carries no meaning."""
    if after.version != before.version:
        raise TransitionError("version", None)
    old, new = _by_id(before), _by_id(after)
    for link_id, link in old.items():
        if link_id not in new:
            raise TransitionError("removal", link_id)
        _check_link(link, new[link_id])
    for link_id, link in new.items():
        if link_id not in old and link.state != "pending":
            raise TransitionError("not-allowed", link_id, f"added as {link.state}")


# --- signers -------------------------------------------------------------------------------------------------
#
# Everything below reads git objects and signatures only and never parses YAML (D2): a crafted ledger.yaml can
# crash the parser, but not the check that decides whether its commit may be applied at all.

GIT_TIMEOUT = 30
LEDGER_PATH = "ledger.yaml"
Signer = Literal["operator", "ledger", "untrusted"]
# Who GitHub records as the committer of each commit it makes and signs with its web-flow key (web-editor commits,
# merge, squash and rebase buttons, "Update branch"). Only the reason a freeze gives reads it (see walk()); it
# never makes a commit valid, and anyone can write it.
GITHUB_COMMITTER = ("GitHub", "noreply@github.com")

_SHA = re.compile(r"[0-9a-f]{40}")
_FPR = re.compile(r"[0-9A-Fa-f]{40}")
_RANGE = re.compile(r"([0-9a-fA-F]{40})\.\.([0-9a-fA-F]{40})")
# git's own environment for every call. Every inherited GIT_* variable is dropped first: they can inject
# config (`git -c` travels as GIT_CONFIG_PARAMETERS) or point git at another repository, index or object
# store. No user or system gitconfig is read either, so only the checkout's own .git/config applies, and
# neither replace refs nor a .git/info/grafts file may rewrite a commit's parents.
_GIT_ENV = {"LC_ALL": "C", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull, "GIT_TERMINAL_PROMPT": "0"}


class GitError(RuntimeError):
    """A git call failed: the walk can't decide, so the caller fails closed."""


@dataclass(frozen=True)
class Trust:
    """people-trust.json: the primary-key fingerprints of the two signer classes sso-people trusts. There is no
    web-flow class, and gnupg-people doesn't hold web-flow's key."""
    operators: frozenset[str]
    ledger: frozenset[str]


def load_trust(path: Path) -> Trust:
    """Read people-trust.json, {"operators": [...], "ledger": [...]}, or raise ValueError: on any other key (a
    `web_flow` list from the old format included, even empty), a value that isn't 40 hex, or a fingerprint in
    both classes."""
    data = json.loads(Path(path).read_text())
    names = ("operators", "ledger")
    if type(data) is not dict or set(data) != set(names):
        raise ValueError(f"{path}: needs exactly the keys {', '.join(names)}")
    classes = {}
    for name in names:
        fprs = data[name]
        if type(fprs) is not list or not all(type(f) is str and _FPR.fullmatch(f) for f in fprs):
            raise ValueError(f"{path}: {name} must be a list of 40-hex fingerprints")
        classes[name] = frozenset(f.upper() for f in fprs)
    if classes["operators"] & classes["ledger"]:
        raise ValueError(f"{path}: a fingerprint is in both operators and ledger")
    return Trust(**classes)


def _need_sha(sha: str) -> str:
    if type(sha) is not str or not _SHA.fullmatch(sha):
        raise ValueError("expected a full lowercase commit sha")
    return sha


def _git(repo: Path, *args: str, gnupghome: Path | None = None,
         ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(_GIT_ENV)
    if gnupghome is not None:
        env["GNUPGHOME"] = str(gnupghome)
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env, timeout=GIT_TIMEOUT)
    if r.returncode not in ok:
        err = r.stderr.decode(errors="replace").strip().splitlines()
        raise GitError(f"git {args[0]} exited {r.returncode}" + (f": {err[0][:200]}" if err else ""))
    return r


def _exists(repo: Path, sha: str) -> bool:
    return _git(repo, "cat-file", "-e", f"{sha}^{{commit}}", ok=(0, 1, 128)).returncode == 0


def _need_commit(repo: Path, sha: str) -> str:
    if not _exists(repo, _need_sha(sha)):
        raise GitError(f"commit {sha[:7]} is not in {repo}")
    return sha


def _rev_list(repo: Path, *args: str) -> list[str]:
    return _git(repo, "rev-list", *args).stdout.decode().split()


def commit_signer(repo: Path, sha: str, keyring: Path, trust: Trust) -> Signer:
    """The class of the key that signed `sha`, verified against `keyring`. Only a good signature (G) from a
    key with a class counts; the class comes from the primary key's fingerprint (%GP), so a subkey signs for
    its primary. Unsigned, unknown, expired, revoked or untrusted keys are all "untrusted", and so is GitHub's
    web-flow key, which gnupg-people doesn't hold."""
    out = _git(repo, "log", "-1", "--no-show-signature", "--format=%G?%x00%GP", _need_sha(sha),
               gnupghome=keyring).stdout.decode(errors="replace")
    status, sep, fpr = out.rstrip("\n").partition("\0")
    if not sep or status != "G":
        return "untrusted"
    fpr = fpr.strip().upper()
    if fpr in trust.operators:
        return "operator"
    if fpr in trust.ledger:
        return "ledger"
    return "untrusted"


def _commit_object(repo: Path, sha: str) -> tuple[list[str], bool]:
    """A commit's parents and whether it carries a signature header, read from the raw object."""
    raw = _git(repo, "cat-file", "commit", sha).stdout
    header = raw.split(b"\n\n", 1)[0].split(b"\n")
    parents = [line[7:].decode() for line in header if line.startswith(b"parent ")]
    signed = any(line.startswith((b"gpgsig ", b"gpgsig-sha256 ")) for line in header)
    return parents, signed


def check_commit(repo: Path, sha: str, signer: str) -> str | None:
    """None if `signer` may make commit `sha`, else why not (D4).

    An operator key may change any path. The ledger key may change ledger.yaml alone, in a commit with one
    parent, as one `:100644 100644 <a> <b> M ledger.yaml` line of `git diff-tree --raw --no-renames -r <parent>
    <sha>`. Anyone else, GitHub's web-flow key included, makes the commit invalid: `unsigned` or
    `untrusted-signer`. A class this module doesn't have raises ValueError."""
    sha = _need_sha(sha)
    if signer not in ("operator", "ledger", "untrusted"):
        raise ValueError(f"unknown signer class {signer}")
    if signer == "operator":
        return None
    parents, signed = _commit_object(repo, sha)
    if signer == "untrusted":
        return "untrusted-signer" if signed else "unsigned"
    if len(parents) != 1:
        return "ledger-merge"
    raw = _git(repo, "diff-tree", "-z", "--raw", "--no-renames", "-r", "--ignore-submodules=none",
               parents[0], sha).stdout
    fields = raw.split(b"\0")
    entries = [(fields[i], fields[i + 1]) for i in range(0, len(fields) - 1, 2)]
    if len(entries) > 1:
        return "ledger-path"
    if not entries:
        return "ledger-status"
    meta, path = entries[0]
    src_mode, dst_mode, _src, _dst, status = meta.lstrip(b":").decode().split(" ")
    if path != LEDGER_PATH.encode():
        return "ledger-path"
    if any(mode not in ("100644", "000000") for mode in (src_mode, dst_mode)):  # 000000: a side that is absent
        return "ledger-mode"
    if status != "M":
        return "ledger-status"
    return None


# --- the walk and recovery -----------------------------------------------------------------------------------

def parse_reviewed_range(trailer_values: str) -> tuple[str, str] | None:
    """The (last good, tip) pair of a Reviewed-Range trailer. Exactly one trailer whose value is `<sha>..<sha>`,
    both full 40-hex shas; anything else is None.

    `trailer_values` is what `git log -1 --format=%(trailers:key=Reviewed-Range,valueonly) <sha>` prints, one
    value per line, never a commit message: git's own parser decides what counts as a trailer, and a whole
    message handed in here is refused like any malformed value."""
    values = [v.strip() for v in trailer_values.splitlines() if v.strip()]
    if len(values) != 1:
        return None
    m = _RANGE.fullmatch(values[0])
    return (m.group(1).lower(), m.group(2).lower()) if m else None


def _trailer(repo: Path, sha: str) -> str:
    return _git(repo, "log", "-1", "--no-show-signature", "--format=%(trailers:key=Reviewed-Range,valueonly)",
                sha).stdout.decode(errors="replace")


def _web_ui_attempt(repo: Path, sha: str) -> bool:
    """Whether `sha` reads as a Reviewed-Range commit made in GitHub's web UI: committed as GitHub, with a
    Reviewed-Range trailer. Its caller asks only about commits signed by a key the box doesn't hold. This only
    words a freeze's reason; anyone can write a commit that reads so, and it never makes a commit valid."""
    out = _git(repo, "log", "-1", "--no-show-signature",
               "--format=%cn%x00%ce%x00%(trailers:key=Reviewed-Range,valueonly)", sha).stdout.decode(errors="replace")
    name, _, rest = out.partition("\0")
    email, _, trailers = rest.partition("\0")
    return (name, email) == GITHUB_COMMITTER and bool(trailers.strip())


@dataclass(frozen=True)
class WalkVerdict:
    head: str
    last_good: str                       # the last good commit after this walk: the head when valid
    valid: bool
    reason: str | None                   # why not valid; None when valid
    chain: list[tuple[str, str]]         # (commit, signer class), oldest first
    invalid: list[tuple[str, str]]       # (commit, code) of the commits that freeze, oldest first
    recovery: str | None                 # the Reviewed-Range commit the box took, if any
    newest_trusted: str                  # where check mode applies people.yaml from: see newest_trusted()
    seen_heads: list[str] = field(default_factory=list)   # what the caller stores as seen heads: see walk()


def _graph(repo: Path, *tips: str) -> tuple[list[str], dict[str, list[str]]]:
    """Every commit reachable from `tips`, parents before children, with each one's parents. One full walk
    (`rev-list --parents`, no exclusions), so no date-based cut-off applies; ancestry is then computed here."""
    out = _git(repo, "rev-list", "--topo-order", "--reverse", "--parents", *tips).stdout.decode().splitlines()
    order, parents = [], {}
    for line in out:
        c, *ps = line.split()
        order.append(c)
        parents[c] = ps
    return order, parents


def _ancestors(parents: dict[str, list[str]], tip: str) -> set[str]:
    """`tip` and everything reachable from it; empty if `tip` isn't in the graph."""
    seen, stack = set(), [tip]
    while stack:
        c = stack.pop()
        if c not in seen and c in parents:
            seen.add(c)
            stack.extend(parents[c])
    return seen


class _Graph:
    """One full read of the commit graph under a head and last good, and what the walk learns about each commit
    (its signer and code, its Reviewed-Range trailer), each read from git once. The walk of the head and every
    candidate walk newest_trusted makes share it: a candidate's history lies inside the head's, so a candidate
    costs set operations, not git calls."""

    def __init__(self, repo: Path, head: str, last_good: str):
        self.order, self.parents = _graph(repo, head, last_good)
        self.pos = {c: i for i, c in enumerate(self.order)}
        self.done = _ancestors(self.parents, last_good)          # last good's history
        self.signers: dict[str, str] = {}
        self.codes: dict[str, str | None] = {}
        self.trailers: dict[str, str] = {}
        self.web_ui: dict[str, bool] = {}
        self._ancestors: dict[str, set[str]] = {}

    def ancestors(self, tip: str) -> set[str]:
        if tip not in self._ancestors:
            self._ancestors[tip] = _ancestors(self.parents, tip)
        return self._ancestors[tip]

    def above(self, tip: str) -> set[str]:
        """`tip` and everything reachable from it that last good's history lacks: the range a walk of `tip`
        checks. It never enters last good's history, so its cost is the range's size, not the repository's."""
        seen, stack = set(), [tip]
        while stack:
            c = stack.pop()
            if c not in seen and c not in self.done and c in self.parents:
                seen.add(c)
                stack.extend(self.parents[c])
        return seen

    def check(self, repo: Path, c: str, keyring: Path, trust: Trust) -> str | None:
        if c not in self.codes:
            self.signers[c] = commit_signer(repo, c, keyring, trust)
            self.codes[c] = check_commit(repo, c, self.signers[c])
        return self.codes[c]

    def trailer(self, repo: Path, c: str) -> str:
        if c not in self.trailers:
            self.trailers[c] = _trailer(repo, c)
        return self.trailers[c]

    def web_ui_attempt(self, repo: Path, c: str) -> bool:
        if c not in self.web_ui:
            self.web_ui[c] = _web_ui_attempt(repo, c)
        return self.web_ui[c]


def _seen_heads(value: list[str] | None) -> list[str]:
    """The caller's seen heads as a validated list, in order and once each. None means an empty list."""
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        raise ValueError("seen_heads must be a list of shas")
    out: list[str] = []
    for sha in value:
        sha = _need_sha(sha)
        if sha not in out:
            out.append(sha)
    return out


def _recorded(seen: list[str], head: str) -> list[str]:
    return seen if head in seen else [*seen, head]


# Errors a candidate walk may raise; newest_trusted then gives last good.
_WALK_ERRORS = (GitError, ValueError, OSError, subprocess.SubprocessError)


def newest_trusted(repo: Path, head: str, last_good: str, keyring: Path, trust: Trust) -> str:
    """Where check mode applies people.yaml from (D10, as ruled): the newest commit C on head's first-parent line
    that has last good in its history, is operator-signed or a path-valid ledger-key commit, and for which
    walk(C, last_good) is valid (no seen heads asked: they add no content check now that every commit is checked
    by its own signer); else last good itself. Never None.

    So check mode applies what apply mode would have taken, stopping before the first problem: an operator
    commit on top of an invalid one vouches for nothing, a ledger-key commit counts once its walk is valid, and
    a rollback, a sibling or a merge that brings last good in only on another parent gives last good, never a
    people.yaml from before it. Last good counts whoever signed it (the changeover anchor is web-flow's). When
    head itself walks valid it is the answer, also when a recovery took history that doesn't fast-forward (an
    erasure), since an operator named that range.

    Cost: one graph read and one signature check per commit in the range, shared by every candidate. Candidates
    are tried newest first, each a walk over the shared graph (set operations, O(range)), stopping at the first
    valid one: O(candidates x range) set operations at worst, and no further git calls but a trailer read per
    operator commit. Fail-closed: bad input raises (ValueError, or GitError for a commit not in the checkout);
    any error while searching gives last good."""
    _need_commit(repo, head)
    _need_commit(repo, last_good)
    try:
        if _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() != b"false":
            return last_good
        g = _Graph(repo, head, last_good)
    except _WALK_ERRORS:
        return last_good
    return _newest_valid(repo, g, head, last_good, keyring, trust)


def _newest_valid(repo: Path, g: _Graph, head: str, last_good: str, keyring: Path, trust: Trust) -> str:
    """newest_trusted's search over a graph already read."""
    try:
        if _judge(repo, g, head, last_good, keyring, trust, []).valid:
            return head
        descends = set()                                 # commits with last good in their history
        for c in g.order:                                # parents before children
            if c == last_good or any(p in descends for p in g.parents[c]):
                descends.add(c)
        # Down head's first-parent line, newest first. A commit lacking last good has a first parent lacking it
        # too, so the first such commit ends the search.
        c = head
        while c in descends and c != last_good:
            if c != head and g.check(repo, c, keyring, trust) is None \
                    and _judge(repo, g, c, last_good, keyring, trust, []).valid:
                return c
            c = g.parents[c][0]                          # c isn't last good, so it has parents
    except _WALK_ERRORS:
        pass
    return last_good


def walk(repo: Path, head: str, last_good: str, keyring: Path, trust: Trust,
         seen_heads: list[str] | None = None) -> WalkVerdict:
    """Check `last_good..head` (D5, as Task 2b left it: no web-flow on sso-people).

    - Every commit in the range is checked by its own signer. The range is every commit in head's history that
      last good's history lacks, on any parent. An operator key may change any path, the ledger key ledger.yaml
      alone (check_commit), and anything else, GitHub's web-flow key included, makes the commit invalid. No merge
      exempts what it brings in: GitHub's merge, squash and rebase buttons and "Update branch" make web-flow
      commits, which are invalid themselves, and an operator's local merge brings nothing in unchecked.
    - The chain is head's first-parent line down to last good's history: what the verdict reports, and where a
      recovery commit is looked for. Head must fast-forward from last good.
    - `seen_heads`, every head the box has seen since last good (valid or not, in order), is defence in depth:
      each one that is not in last good's history must sit on head's first-parent line, or the walk freezes
      with `not-first-parent-descendant@<it>`, naming the first offender. A seen head off the line was brought
      in on another parent (an "Update branch" merge, a PR into another base) or force-pushed away. None or []
      (a first run, a rebuilt box) asks nothing. The verdict's `seen_heads` is what the caller stores: the list
      with this head added when the walk froze, so a freeze stays until a recovery, or [] when it was valid and
      last good moved to head.
    - A recovery commit is the newest chain commit an operator key signed whose trailer is `<L>..<T>`. The box
      takes it only if L is its last good and T an ancestor of it, and then reviews T's history less last good's.
      It overrides the fast-forward and seen-heads checks, and nothing else: every commit outside the reviewed
      set is still checked by its own signer, and every seen head still in head's history must be on the line
      or inside the reviewed set (else `recovery-misses@<it>`). A seen head gone from history asks nothing, since
      none of its changes land.

    So a commit in a valid history that neither an operator key nor a path-valid ledger-key signature vouches
    for is inside a range an operator named in a Reviewed-Range, or was taken before (last good's history).
    A box with no state, a first run or a rebuild, takes last good from the anchor the operator recorded
    (people_anchor_commit) and from nothing else (D6): an operator commit made on top of an invalid one vouches
    for nothing, so the walk from the anchor meets the invalid commit and freezes until a Reviewed-Range.

    Reasons, frozen: the newest failed operator attempt; then a Reviewed-Range commit GitHub's web UI made
    (`recovery-not-operator-key@`, read from its committer and never trusted); then the first invalid commit;
    the first stray; `not-fast-forward`. Under a taken recovery: `recovery-misses@` for an invalid commit inside
    the recovery's own history, else `invalid:<code>@`; then `recovery-misses@` for a seen head left out.

    Ranges come from ancestry, never from `git rev-list A ^B`: that stops walking B's history a few commits
    after only excluded ones are left (git's SLOP), so commit dates, which signers choose, could pull
    already-checked history back into the range."""
    _need_commit(repo, head)
    _need_commit(repo, last_good)
    seen = _seen_heads(seen_heads)
    if _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() != b"false":
        # A shallow checkout cuts parents off, so the walk can't see the whole range: refuse it. The head is
        # still recorded: a full clone later must not let it in unchecked. Check mode stays at last good.
        return WalkVerdict(head=head, last_good=last_good, valid=False, reason="shallow-repository", chain=[],
                           invalid=[], recovery=None, newest_trusted=last_good, seen_heads=_recorded(seen, head))
    g = _Graph(repo, head, last_good)
    v = _judge(repo, g, head, last_good, keyring, trust, seen)
    return replace(v, newest_trusted=head if v.valid else _newest_valid(repo, g, head, last_good, keyring, trust))


def _judge(repo: Path, g: _Graph, head: str, last_good: str, keyring: Path, trust: Trust,
           seen: list[str]) -> WalkVerdict:
    """walk()'s verdict on `head` over the shared graph `g`, with newest_trusted left at last good."""
    parents, done = g.parents, g.done
    above = g.above(head)                                # the range: head's history less last good's
    # Head fast-forwards if last good is in its history: then some commit in the range has it as a parent.
    fast_forward = head == last_good or any(last_good in parents[c] for c in above)
    order, c = [], head                                  # the first-parent chain, oldest first
    while c not in done:
        order.append(c)
        if not parents[c]:
            break
        c = parents[c][0]
    order.reverse()
    strays: list[str] = []
    if seen:
        line, c = set(), head                            # head's whole first-parent line
        while c in parents and c not in line:
            line.add(c)
            c = parents[c][0] if parents[c] else None
        # Seen heads off the line: each is either in head's history on another parent (brought in by a merge)
        # or gone from it (force-pushed away). A seen head already in last good's history asks nothing.
        strays = [s for s in seen if s not in done and s not in line]
    # Every commit in the range, parents before children, each checked by its own signer: the chain and
    # whatever any merge brings in alike. Under a recovery too, so nothing outside the reviewed range goes
    # unchecked.
    everything = sorted(above, key=g.pos.__getitem__)
    for c in everything:
        g.check(repo, c, keyring, trust)
    signers, codes = g.signers, g.codes
    chain = [(c, signers[c]) for c in order]

    # Newest first: the recovery candidate is the newest operator-signed commit with a well-formed trailer, and
    # a newer operator attempt that failed names the problem. A trailer on any other commit is no attempt, so
    # a ledger-key, unsigned or unknown-key commit can never mask the freeze's reason; the one exception is
    # wording only, a commit GitHub's web UI made (an operator's likely mistake), and it ranks below every
    # operator attempt.
    operator_problem, web_ui_problem, candidate = None, None, None
    for c in reversed(order):
        if signers[c] == "operator":
            text = g.trailer(repo, c)
            if not text.strip():
                continue
            parsed = parse_reviewed_range(text)
            if parsed is not None:
                candidate = (c, *parsed)
                break
            operator_problem = operator_problem or f"recovery-bad-trailer@{c[:7]}"
        elif web_ui_problem is None and codes[c] == "untrusted-signer" and g.web_ui_attempt(repo, c):
            web_ui_problem = f"recovery-not-operator-key@{c[:7]}"

    recovery, reviewed, under_recovery = None, set(), set()
    if candidate is not None:
        rec, named_last_good, tip = candidate
        under_recovery = g.ancestors(rec)
        if named_last_good != last_good:
            operator_problem = operator_problem or f"recovery-stale-last-good@{rec[:7]}"
        elif tip == rec or tip not in under_recovery:
            operator_problem = operator_problem or f"recovery-tip-not-ancestor@{rec[:7]}"
        else:
            recovery = rec
            reviewed = g.ancestors(tip) - done

    invalid = [(c, codes[c]) for c in everything if codes[c] is not None and c not in reviewed]
    if recovery is not None:
        # A seen head still in head's history, off the line and outside the range, was never reviewed; one gone
        # from history lands nothing and asks nothing.
        missed = [s for s in strays if s in above and s not in reviewed]
        valid = not invalid and not missed
        reason = None
        if invalid:                      # in the recovery's own history it should have been reviewed
            c, code = invalid[0]
            reason = f"recovery-misses@{c[:7]}" if c in under_recovery else f"invalid:{code}@{c[:7]}"
        elif missed:
            reason = f"recovery-misses@{missed[0][:7]}"
    else:
        valid = fast_forward and not strays and not invalid
        reason = None
        if not valid:
            if operator_problem or web_ui_problem:
                reason = operator_problem or web_ui_problem
            elif invalid:
                c, code = invalid[0]
                reason = f"invalid:{code}@{c[:7]}"
            elif strays:
                reason = f"not-first-parent-descendant@{strays[0][:7]}"
            else:
                reason = "not-fast-forward"
    # Valid: last good moves to head and the seen list clears. Frozen: this head joins it, whatever the reason.
    return WalkVerdict(head=head, last_good=head if valid else last_good, valid=valid, reason=reason,
                       chain=chain, invalid=invalid, recovery=recovery if valid else None,
                       newest_trusted=last_good, seen_heads=[] if valid else _recorded(seen, head))


# --- reading a file at a commit ------------------------------------------------------------------------------

EMPTY_LEDGER = Ledger(1, ())


def _tree_entry(repo: Path, sha: str, path: str) -> tuple[str, str, str, int | None] | None:
    """(mode, type, object, size) of `path` at the top of commit `sha`'s tree, or None if it isn't there."""
    out = _git(repo, "ls-tree", "-l", "-z", _need_sha(sha), "--", path).stdout
    for record in out.split(b"\0"):
        meta, sep, name = record.partition(b"\t")
        if sep and name == path.encode():
            mode, kind, obj, size = meta.decode().split()
            return mode, kind, obj, (None if size == "-" else int(size))
    return None


def ledger_at(repo: Path, sha: str) -> Ledger:
    """ledger.yaml at commit `sha`, parsed strictly (parse_ledger); a commit without one holds the empty ledger.
    Raises SchemaError: `type` when it isn't a regular file (a symlink, a submodule, a directory), `too-large`
    before reading a blob over the limit."""
    entry = _tree_entry(repo, sha, LEDGER_PATH)
    if entry is None:
        return EMPTY_LEDGER
    mode, kind, obj, size = entry
    if kind != "blob" or mode not in ("100644", "100755"):
        raise SchemaError("type", "ledger.yaml is not a regular file")
    if size is not None and size > MAX_LEDGER_BYTES:
        raise SchemaError("too-large", f"{size} bytes, at most {MAX_LEDGER_BYTES}")
    return parse_ledger(_git(repo, "cat-file", "blob", obj).stdout)


def _file_at(repo: Path, sha: str, path: str) -> bytes | None:
    entry = _tree_entry(repo, sha, path)
    if entry is None:
        return None
    mode, kind, obj, _size = entry
    if kind != "blob" or mode not in ("100644", "100755"):
        raise ValueError(f"{path} at {sha[:7]} is not a regular file")
    return _git(repo, "cat-file", "blob", obj).stdout


def _operator_yaml(data: bytes, what: str):
    """An operator-owned file (people.yaml, reserved.yaml) as plain data. A YAML error's own text quotes the
    file, so only the file's name is kept."""
    try:
        return yaml.safe_load(data)
    except (yaml.YAMLError, RecursionError, UnicodeDecodeError):
        raise ValueError(f"{what} is not valid YAML") from None


# --- the ledger verdict --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class LedgerVerdict:
    effective: str | None        # the commit whose ledger.yaml is the ledger now: the head, or the last good ledger
    refused: bool
    reason: str | None           # when refused: schema:<code>@<sha7> or transition:<code>@<sha7>


def _first_parent_line(repo: Path, head: str, base: str | None) -> tuple[list[str], dict[str, list[str]]]:
    """head's first-parent line down to `base`'s history, oldest first, and the graph's parents. Ancestry comes
    from one full rev-list, as in walk(); base None runs to the root."""
    _order, parents = _graph(repo, head, *([base] if base else []))
    done = _ancestors(parents, base) if base else set()
    line, c = [], head
    while c not in done:
        line.append(c)
        if not parents[c]:
            break
        c = parents[c][0]
    line.reverse()
    return line, parents


def check_ledger(repo: Path, verdict: WalkVerdict, last_good_ledger: str | None,
                 signers: Mapping[str, str] | None = None) -> LedgerVerdict:
    """Whether ledger.yaml at a validly walked head becomes the ledger, or the box keeps the last good ledger
    (`last_good_ledger`, the commit whose ledger.yaml it took last).

    It reads head's first-parent line down to the last good ledger's history: what the head's ledger.yaml grew
    from since then. The newest commit on it that an operator key signed and that changes ledger.yaml is an
    operator edit: the operator vouches for the whole file (hand entries, overrides, an erasure may break the
    transitions), and only the schema applies to it. Every ledger.yaml change after it, or after the last good
    ledger if there is none, is held to the ledger key's rights: check_transition against its parent. Only the
    ledger key may make such a change; a commit with no known class, or one inside a reviewed range
    (`untrusted`), is held to the same rights, the closed direction. Classes come from `signers` (the walk command
    records the line's in walk.json's ledger_chain), else from verdict.chain.

    Valid: effective is the head. Any schema or transition failure refuses the ledger: effective stays at the
    last good ledger, the reason names the first failing commit (`schema:<code>@<sha7>`,
    `transition:<code>@<sha7>`), and later ledger changes wait behind it until an operator edit. A missing
    ledger.yaml is the empty ledger. A frozen walk takes nothing: the last good ledger, not refused.

    Raises GitError (the last good ledger gone from the checkout, say) or ValueError on bad input; the content
    step then fails, and a failed content step never blocks people.yaml."""
    if not verdict.valid:
        return LedgerVerdict(last_good_ledger, False, None)
    head = _need_commit(repo, verdict.head)
    if last_good_ledger is not None:
        _need_commit(repo, last_good_ledger)
    line, parents = _first_parent_line(repo, head, last_good_ledger)
    classes = dict(verdict.chain)
    classes.update(signers or {})
    entries: dict[str, tuple[str, str, str] | None] = {}

    def entry(c: str | None) -> tuple[str, str, str] | None:
        if c is None:
            return None
        if c not in entries:
            e = _tree_entry(repo, c, LEDGER_PATH)
            entries[c] = None if e is None else e[:3]
        return entries[c]

    def first_parent(c: str) -> str | None:
        return parents[c][0] if parents[c] else None

    def changes(c: str) -> bool:
        return entry(c) != entry(first_parent(c))

    def refuse(kind: str, code: str, c: str) -> LedgerVerdict:
        return LedgerVerdict(last_good_ledger, True, f"{kind}:{code}@{c[:7]}")

    edit = next((i for i in range(len(line) - 1, -1, -1)
                 if classes.get(line[i]) == "operator" and changes(line[i])), None)
    if edit is not None:
        base, rest = line[edit], line[edit + 1:]
    else:
        base, rest = (first_parent(line[0]) if line else head), line
    try:
        before = ledger_at(repo, base) if base is not None else EMPTY_LEDGER
    except SchemaError as e:
        return refuse("schema", e.code, base)
    for c in rest:
        if not changes(c):
            continue
        try:
            after = ledger_at(repo, c)
        except SchemaError as e:
            return refuse("schema", e.code, c)
        try:
            check_transition(before, after)
        except TransitionError as e:
            return refuse("transition", e.code, c)
        before = after
    return LedgerVerdict(head, False, None)


# --- people.yaml and reserved names --------------------------------------------------------------------------

@dataclass(frozen=True)
class People:
    """What admission reads from people.yaml at the walked head: each username's tier (realliance, member, guest
    or inactive), and every username and bootstrap email (trimmed, in lower case) a new guest may not take."""
    tiers: dict[str, str]
    usernames: set[str]
    emails: set[str]


def load_people(repo: Path, sha: str) -> People:
    """people.yaml at commit `sha`. An inactive entry is `inactive`. An active one in /guests is `guest`, an
    emergency-override entry; it wins over any other group, the closed direction. Else active in /realliance is
    `realliance`, and any other active entry `member`. Raises ValueError on a file that isn't people.yaml, a
    username twice included, never quoting the file."""
    data = _file_at(repo, sha, "people.yaml")
    if data is None:
        raise ValueError(f"people.yaml is missing at {sha[:7]}")
    doc = _operator_yaml(data, "people.yaml")
    if type(doc) is not dict or type(doc.get("people")) is not list:
        raise ValueError("people.yaml needs a people list")
    tiers: dict[str, str] = {}
    emails: set[str] = set()
    for i, p in enumerate(doc["people"]):
        if type(p) is not dict or type(p.get("username")) is not str or type(p.get("active")) is not bool:
            raise ValueError(f"people.yaml: entry {i} needs a username and active")
        groups = p.get("groups") or []
        if type(groups) is not list or not all(type(g) is str for g in groups):
            raise ValueError(f"people.yaml: entry {i} groups must be a list")
        u = p["username"].strip().lower()
        if u in tiers:
            raise ValueError(f"people.yaml: entry {i} repeats a username")
        tiers[u] = ("inactive" if not p["active"] else "guest" if "/guests" in groups
                    else "realliance" if "/realliance" in groups else "member")
        boot = p.get("bootstrap")
        if boot is not None:
            if type(boot) is not dict or type(boot.get("email")) is not str:
                raise ValueError(f"people.yaml: entry {i} bootstrap needs an email")
            emails.add(normal_email(boot["email"]))
    return People(tiers, set(tiers), emails)


RESERVED_NAMES = frozenset((
    "admin root www sso git api mail invites invite guests forgejo forgejo-admin forge-bot forge-ci ops-ci "
    "ci-dispatch realliance realliance-ops realliance-ci realmic ghost").split())
RESERVED_PREFIXES = ("test-", "ci-", "admin-")
RESERVED_FILE = "reserved.yaml"


def load_reserved(repo: Path, sha: str) -> tuple[frozenset[str], tuple[str, ...]]:
    """The reserved usernames and prefixes: the built-ins plus private reserved.yaml at commit `sha` if present,
    `{reserved: [...], reserved_prefixes: [...]}`, in lower case. Raises ValueError on any other shape."""
    names, prefixes = set(RESERVED_NAMES), list(RESERVED_PREFIXES)
    data = _file_at(repo, sha, RESERVED_FILE)
    if data is not None:
        doc = _operator_yaml(data, RESERVED_FILE)
        doc = {} if doc is None else doc
        if type(doc) is not dict or not set(doc) <= {"reserved", "reserved_prefixes"}:
            raise ValueError("reserved.yaml takes reserved and reserved_prefixes only")
        lists = {}
        for key in ("reserved", "reserved_prefixes"):
            values = [] if doc.get(key) is None else doc[key]
            if type(values) is not list or not all(type(v) is str and v.strip() for v in values):
                raise ValueError(f"reserved.yaml: {key} must be a list of names")
            lists[key] = [v.strip().lower() for v in values]
        names.update(lists["reserved"])
        prefixes += [p for p in lists["reserved_prefixes"] if p not in prefixes]
    return frozenset(names), tuple(prefixes)


# --- formats (D20) -------------------------------------------------------------------------------------------

_USERNAME = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}")
_EMAIL_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
# Keycloak's person-name-prohibited-characters, which its user profile applies to first and last names.
NAME_PROHIBITED = frozenset('<>&"$%!#?§;*~/\\|^=[]{}()')
MAX_EMAIL = 254
MAX_NAME = 64


def username_ok(u) -> bool:
    return type(u) is str and _USERNAME.fullmatch(u) is not None and "--" not in u


def name_ok(n) -> bool:
    """1-64 characters, none of Keycloak's prohibited characters and no control character (category Cc)."""
    return (type(n) is str and 1 <= len(n) <= MAX_NAME
            and not any(ch in NAME_PROHIBITED or unicodedata.category(ch) == "Cc" for ch in n))


def normal_email(e: str) -> str:
    """How every email compares, everywhere: trimmed and in lower case."""
    return e.strip().lower()


def email_ok(e) -> bool:
    """ASCII, at most 254 characters once trimmed, one local part of at most 64 and a dotted domain."""
    if type(e) is not str:
        return False
    e = e.strip()
    if not e.isascii() or not 0 < len(e) <= MAX_EMAIL or e.count("@") != 1:
        return False
    local, domain = e.split("@")
    labels = domain.split(".")
    return (_EMAIL_LOCAL.fullmatch(local) is not None and not local.startswith(".") and not local.endswith(".")
            and ".." not in local and len(labels) >= 2 and all(_EMAIL_LABEL.fullmatch(x) for x in labels))


# --- the Keycloak lookup -------------------------------------------------------------------------------------

class LookupFailed(Exception):
    """A Keycloak lookup that couldn't answer: the entry waits for a later run, never refused."""


@runtime_checkable
class Directory(Protocol):
    """Who exists in Keycloak's realliance realm. Both raise LookupFailed when they can't answer."""

    def username_taken(self, u: str) -> bool: ...

    def email_taken(self, e: str) -> bool: ...


class KeycloakDirectory:
    """Directory over Keycloak's admin API as the view-only master service account tofu-plan (D19), its secret
    read from `secret_file` at the first lookup. Every request times out after 10 s. Queries ask for exact
    matches and are compared again here, trimmed and in lower case. A failure raises LookupFailed with no value,
    secret or URL in it and no chained exception, since the URL holds the value asked about."""

    client_id = "tofu-plan"
    timeout = 10
    realm = "realliance"
    MAX_BODY = 1_048_576

    def __init__(self, base_url: str, secret_file: Path):
        self.base_url = base_url.rstrip("/")
        self.secret_file = Path(secret_file)
        self._token: str | None = None

    def _send(self, req: urllib.request.Request) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return getattr(r, "status", 200), r.read(self.MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            e.close()
            return e.code, b""
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:  # timeouts: OSError
            raise LookupFailed(f"keycloak unreachable ({type(e).__name__})") from None

    def _json(self, data: bytes):
        if len(data) > self.MAX_BODY:
            return None
        try:
            return json.loads(data)
        except ValueError:
            return None

    def _fetch_token(self) -> str:
        try:
            secret = self.secret_file.read_text().strip()
        except (OSError, UnicodeDecodeError):
            raise LookupFailed("the lookup secret is unreadable") from None
        if not secret:
            raise LookupFailed("the lookup secret is empty") from None
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": secret}).encode()
        req = urllib.request.Request(f"{self.base_url}/realms/master/protocol/openid-connect/token", data=body,
                                     method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
        status, data = self._send(req)
        doc = self._json(data) if status == 200 else None
        token = doc.get("access_token") if type(doc) is dict else None
        if type(token) is not str or not token:
            raise LookupFailed(f"no token (HTTP {status})") from None
        return token

    def _users(self, key: str, value: str) -> list[dict]:
        query = urllib.parse.urlencode({key: value, "exact": "true", "max": "20"})
        url = f"{self.base_url}/admin/realms/{self.realm}/users?{query}"
        for attempt in (1, 2):
            if self._token is None:
                self._token = self._fetch_token()
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token}",
                                                       "Accept": "application/json"})
            status, data = self._send(req)
            if status == 401 and attempt == 1:       # the token expired: one fresh token, one retry
                self._token = None
                continue
            if status != 200:
                raise LookupFailed(f"user query answered HTTP {status}") from None
            users = self._json(data)
            if type(users) is not list or not all(type(u) is dict for u in users):
                raise LookupFailed("user query answered something other than a list") from None
            return users
        raise LookupFailed("user query unauthorized") from None

    def username_taken(self, u: str) -> bool:
        want = u.strip().lower()
        return any(type(x.get("username")) is str and x["username"].strip().lower() == want
                   for x in self._users("username", want))

    def email_taken(self, e: str) -> bool:
        want = normal_email(e)
        return any(type(x.get("email")) is str and normal_email(x["email"]) == want
                   for x in self._users("email", want))


# --- the box's state -----------------------------------------------------------------------------------------

STATE_VERSION = 1
STATE_FILE = "state.json"
WALK_FILE = "walk.json"
CONTENT_FILE = "content.json"
NEXT_FILE = "guests.next.json"
HANDED_FILE = "handed.json"


@dataclass
class BoxState:
    """state.json (D21). Kept in both modes: last_good, seen_heads (what walk() returned), last_good_ledger and
    `seen`, the box's clock: link id to {"n": the order the box first saw it, "link": when, "redeemed": when it
    first saw the redemption, "hash": the entry it last judged}. Kept in apply only: `admitted`, username to
    {link, at, active} and never an email, and `refused`, link id to {reason, hash}."""
    version: int = STATE_VERSION
    last_good: str | None = None
    seen_heads: list[str] = field(default_factory=list)
    last_good_ledger: str | None = None
    seen: dict[str, dict] = field(default_factory=dict)
    admitted: dict[str, dict] = field(default_factory=dict)
    refused: dict[str, dict] = field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat()


def _from_iso(s: str) -> datetime:
    t = datetime.fromisoformat(s)
    if t.tzinfo is None:
        raise ValueError("a state time without a zone")
    return t


def load_state(dir: Path) -> BoxState:
    """state.json in `dir`; an empty state if there is none (a first run, a rebuilt box). A file that isn't a state
    raises ValueError: the caller fails closed and never starts over on its own."""
    try:
        raw = (Path(dir) / STATE_FILE).read_bytes()
    except FileNotFoundError:
        return BoxState()
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("state.json is not JSON") from None
    names = [f.name for f in fields(BoxState)]
    if type(data) is not dict or set(data) != set(names):
        raise ValueError("state.json: unexpected keys")
    if type(data["version"]) is not int or data["version"] != STATE_VERSION:
        raise ValueError("state.json: unknown version")
    for key in ("last_good", "last_good_ledger"):
        if data[key] is not None:
            _need_sha(data[key])
    if type(data["seen_heads"]) is not list:
        raise ValueError("state.json: seen_heads must be a list")
    data["seen_heads"] = _seen_heads(data["seen_heads"])
    for key in ("seen", "admitted", "refused"):
        if type(data[key]) is not dict or not all(type(k) is str and type(v) is dict for k, v in data[key].items()):
            raise ValueError(f"state.json: {key} must map ids to records")
    for rec in data["seen"].values():
        if type(rec.get("n")) is not int or type(rec.get("link")) is not str:
            raise ValueError("state.json: a seen record needs n and link")
        for key in ("link", "redeemed"):
            if key in rec:
                _from_iso(rec[key])
    for rec in data["admitted"].values():
        if type(rec.get("active")) is not bool or not set(rec) <= {"link", "at", "active"}:
            raise ValueError("state.json: an admitted record is {link, at, active}")
        if rec.get("at") is not None:
            _from_iso(rec["at"])
    return BoxState(**data)


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_json(path: Path, obj) -> None:
    """Replace `path` with `obj` as JSON, atomically and mode 0600: a reader sees the old file or the new one."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = (json.dumps(obj, indent=1) + "\n").encode()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(path.parent)


def save_state(dir: Path, s: BoxState) -> None:
    """Write state.json in `dir` atomically, mode 0600."""
    _write_json(Path(dir) / STATE_FILE, asdict(s))


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


# --- admission -----------------------------------------------------------------------------------------------

REALLIANCE_QUOTA = 5
REALLIANCE_WINDOW = timedelta(days=7)
MEMBER_QUOTA = 1
GLOBAL_CAP = 10
CAP_WINDOW = timedelta(hours=24)
MAX_LIFETIME = timedelta(days=7)
EXPIRY_GRACE = timedelta(minutes=30)
MODES = ("check", "apply")
QUOTA = {"realliance": REALLIANCE_QUOTA, "member": MEMBER_QUOTA}


@dataclass
class Decision:
    admitted_now: list[str]          # usernames admitted this run (apply)
    would_admit: list[str]           # usernames apply would admit (check)
    refused_now: dict[str, str]      # link id to reason, refused this run
    deferred: dict[str, str]         # link id to `cap` or `lookup-failed`
    guests: dict[str, dict]          # the var-file's guests: username to {active, mfa, bootstrap}


def entry_hash(link: Link) -> str:
    """A ledger entry's canonical hash: a refusal stands until it changes."""
    return hashlib.sha256(json.dumps(asdict(link), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _deadline(link: Link, seen: dict) -> datetime:
    """The last moment the box takes a redemption of `link` as on time, and a pending link holds a slot: its first
    sight of the link, plus the link's own lifetime (at most 7 days), plus the grace for apply latency. The
    service's timestamps count only as a length."""
    lifetime = min(parse_time(link.expires) - parse_time(link.created), MAX_LIFETIME)
    return _from_iso(seen["link"]) + lifetime + EXPIRY_GRACE


def _hand(g: Guest) -> dict:
    b = g.bootstrap
    return {"active": g.active, "mfa": g.mfa,
            "bootstrap": {"email": b.email.strip(), "first_name": b.first_name, "last_name": b.last_name}}


def _hand_admitted(ledger: Ledger, adm: dict[str, dict]) -> tuple[dict[str, dict], dict[str, str], set[str]]:
    """Every admitted guest as the var-file hands it, whatever the ledger says now: its entry's profile and active
    (written back to the record), or, for an entry an erasure removed, the stored active and no profile. A guest
    seeded from tofu output (link None) gets its link from the ledger by username. Returns the guests, link id to
    username for every admitted link, and the admitted guests' emails."""
    linked = {rec["link"]: u for u, rec in adm.items() if rec.get("link")}
    for u, rec in adm.items():
        if rec.get("link") is None:
            found = next((x.id for x in ledger.links if x.state == "redeemed" and x.guest.username == u
                          and x.id not in linked), None)
            if found is not None:
                rec["link"], linked[found] = found, u
    by_id = {x.id: x for x in ledger.links}
    guests, emails = {}, set()
    for u, rec in adm.items():
        link = by_id.get(rec.get("link"))
        g = link.guest if link is not None else None
        if g is not None and g.username == u:
            rec["active"] = g.active
            guests[u] = _hand(g)
            emails.add(normal_email(g.bootstrap.email))
        else:
            guests[u] = {"active": rec["active"], "mfa": "webauthn", "bootstrap": None}
    return guests, linked, emails


def admit(ledger: Ledger, people: People, reserved: tuple[frozenset[str], tuple[str, ...]], directory: Directory,
          state: BoxState, now: datetime, mode: str) -> Decision:
    """Decide the guests from the effective ledger, by the box's clock (`now`), and update `state` in place.

    - The clock: the first sight of each link and of each redemption goes into state.seen, in both modes.
    - Admitted guests are handed on every run and never re-checked or dropped; their active follows the ledger.
    - A candidate is a redeemed link not yet admitted. Candidates run in (first sight of the redemption, first
      sight of the link) order; the second is ledger order for links first seen in one run.
    - A refusal stands while the entry's hash is unchanged. A new guest with active false is never created (D8).
    - Refused: username-format, username-reserved, name-format, email-format, inviter-not-member (absent, a
      ledger guest, an override in /guests), inviter-inactive, expired (the redemption seen after the deadline),
      username-taken and email-taken (people.yaml, admitted guests, Keycloak), quota.
    - Quota (D22): count the inviter's other links the box saw before this one that hold a slot now. A pending
      link holds one until its deadline; an admitted one for 7 days after `at` (realliance) or for good (member);
      a redeemed link not yet decided (this run's, or deferred) holds one while it is on time, as the pending
      link it was, so a member never gets two guests whatever order the candidates run in. Refused, revoked,
      expired or inactive links hold none.
    - Deferred, never refused: `cap` with GLOBAL_CAP admissions in the last CAP_WINDOW, this run's included;
      `lookup-failed` when Keycloak can't answer, and then for every later candidate this run, unasked.

    `mode` apply admits (admitted_now, the guests, state.admitted) and keeps refusals; check decides on copies
    (would_admit) and hands only guests admitted before."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    if now.tzinfo is None:
        raise ValueError("now must carry a time zone")
    apply = mode == "apply"
    names, prefixes = reserved
    stamp = _iso(now)
    seen = state.seen
    order = max((rec["n"] for rec in seen.values()), default=-1) + 1
    for link in ledger.links:
        rec = seen.get(link.id)
        if rec is None:
            rec = seen[link.id] = {"n": order, "link": stamp}
            order += 1
        if link.state == "redeemed" and "redeemed" not in rec:
            rec["redeemed"] = stamp
    adm = state.admitted if apply else copy.deepcopy(state.admitted)
    ref = state.refused if apply else copy.deepcopy(state.refused)
    guests, linked, taken_emails = _hand_admitted(ledger, adm)
    taken_emails |= people.emails
    taken_users = set(people.usernames) | set(adm)
    hashes = {x.id: entry_hash(x) for x in ledger.links if x.state == "redeemed"}

    def holds_slot(other: Link, tier: str) -> bool:
        u = linked.get(other.id)
        if u is not None:
            at = adm[u].get("at")
            return tier == "member" or (at is not None and now < _from_iso(at) + REALLIANCE_WINDOW)
        if other.state == "pending":
            return now <= _deadline(other, seen[other.id])
        if other.state == "redeemed" and other.guest.active:
            r = ref.get(other.id)
            if r is not None and r.get("hash") == hashes[other.id]:
                return False
            return _from_iso(seen[other.id]["redeemed"]) <= _deadline(other, seen[other.id])
        return False

    def slots(link: Link, tier: str) -> int:
        n = seen[link.id]["n"]
        return sum(1 for o in ledger.links
                   if o.inviter == link.inviter and o.id != link.id and seen[o.id]["n"] < n and holds_slot(o, tier))

    def recent() -> int:
        return sum(1 for rec in adm.values() if rec.get("at") and now < _from_iso(rec["at"]) + CAP_WINDOW)

    def refusal(link: Link, email: str) -> str | None:
        g = link.guest
        tier = people.tiers.get(link.inviter)
        if not username_ok(g.username):
            return "username-format"
        if g.username in names or g.username.startswith(prefixes):
            return "username-reserved"
        if not name_ok(g.bootstrap.first_name) or (g.bootstrap.last_name is not None
                                                   and not name_ok(g.bootstrap.last_name)):
            return "name-format"
        if not email_ok(g.bootstrap.email):
            return "email-format"
        if tier not in QUOTA:
            return "inviter-inactive" if tier == "inactive" else "inviter-not-member"
        if _from_iso(seen[link.id]["redeemed"]) > _deadline(link, seen[link.id]):
            return "expired"
        if g.username in taken_users:
            return "username-taken"
        if email in taken_emails:
            return "email-taken"
        if slots(link, tier) >= QUOTA[tier]:
            return "quota"
        return None

    candidates = sorted((x for x in ledger.links if x.state == "redeemed" and x.id not in linked),
                        key=lambda x: (_from_iso(seen[x.id]["redeemed"]), seen[x.id]["n"]))
    new, refused_now, deferred = [], {}, {}
    lookups_down = False
    for link in candidates:
        g, h = link.guest, hashes[link.id]
        seen[link.id]["hash"] = h
        old = ref.get(link.id)
        if old is not None:
            if old.get("hash") == h:
                continue
            del ref[link.id]
        if not g.active:
            continue
        email = normal_email(g.bootstrap.email)
        reason = refusal(link, email)
        if reason is None:
            if recent() >= GLOBAL_CAP:
                deferred[link.id] = "cap"
                continue
            if lookups_down:
                deferred[link.id] = "lookup-failed"
                continue
            try:
                if directory.username_taken(g.username):
                    reason = "username-taken"
                elif directory.email_taken(email):
                    reason = "email-taken"
            except LookupFailed:
                lookups_down = True
                deferred[link.id] = "lookup-failed"
                continue
        if reason is not None:
            ref[link.id] = {"reason": reason, "hash": h}
            refused_now[link.id] = reason
            continue
        adm[g.username] = {"link": link.id, "at": stamp, "active": True}
        linked[link.id] = g.username
        taken_users.add(g.username)
        taken_emails.add(email)
        new.append(g.username)
        if apply:
            guests[g.username] = _hand(g)
    return Decision(admitted_now=new if apply else [], would_admit=[] if apply else new, refused_now=refused_now,
                    deferred=deferred, guests=dict(sorted(guests.items())))


# --- statuses ------------------------------------------------------------------------------------------------

STATUS_LIMIT = 140                   # GitHub's limit on a commit status description


def _fit(text: str) -> str:
    return text if len(text) <= STATUS_LIMIT else text[:STATUS_LIMIT - 1] + "…"


def _frozen(prefix: str, reason: str | None, seen_heads: list[str]) -> str:
    """`frozen: <reason>; seen: <sha7>,<sha7> (+N)`: as many seen heads as fit, then how many more."""
    start = f"{prefix}frozen: {reason or 'unknown'}; seen: "
    shown = [s[:7] for s in seen_heads]
    if not shown:
        return _fit(start + "none")
    for k in range(len(shown), -1, -1):
        more = len(shown) - k
        text = start + " ".join(p for p in (",".join(shown[:k]), f"(+{more})" if more else "") if p)
        if len(text) <= STATUS_LIMIT:
            return text
    return _fit(start + f"(+{len(shown)})")


def statuses(mode: str, verdict: WalkVerdict, ledger: LedgerVerdict, decision: Decision) -> dict:
    """The two commit statuses for the walked head, `{state, description}` each, saying what apply does or, in
    check mode, would do (prefixed `check: would be `). sso/apply fails on a freeze; sso/ledger fails when the
    ledger is refused and waits (pending) on a freeze, when nothing reads the ledger. Each description fits a
    status and holds ids and counts only."""
    prefix = "check: would be " if mode == "check" else ""
    if not verdict.valid:
        text = _frozen(prefix, verdict.reason, verdict.seen_heads)
        return {"apply": {"state": "failure", "description": text},
                "ledger": {"state": "pending", "description": text}}
    admitted = len(decision.admitted_now) + len(decision.would_admit)
    applied = _fit(f"{prefix}applied: {admitted} admitted, {len(decision.refused_now)} refused, "
                   f"{len(decision.deferred)} deferred")
    out = {"apply": {"state": "success", "description": applied},
           "ledger": {"state": "success", "description": applied}}
    if ledger.refused:
        out["ledger"] = {"state": "failure", "description": _fit(f"{prefix}ledger refused: {ledger.reason}")}
    return out


def _fallback_statuses(mode: str, verdict: WalkVerdict) -> dict:
    """The statuses to post if the content step fails after this walk: people.yaml applies with the last handed
    guests (fallback), so nothing is admitted, and sso/ledger reads `content failed`."""
    out = statuses(mode, verdict, LedgerVerdict(None, False, None), Decision([], [], {}, {}, {}))
    if verdict.valid:
        prefix = "check: would be " if mode == "check" else ""
        out["ledger"] = {"state": "failure", "description": f"{prefix}content failed"}
    return out


# --- the command line ----------------------------------------------------------------------------------------

class UsageError(Exception):
    """A command the box can't run as asked: exit 2."""


def _ledger_chain(repo: Path, verdict: WalkVerdict, last_good_ledger: str | None, keyring: Path,
                  trust: Trust) -> list[list[str]] | None:
    """Head's first-parent line down to the last good ledger's history with each commit's signer class, oldest
    first: check_ledger needs the classes of commits the walk's own chain no longer covers (last good moved on
    while the ledger stayed refused, or a content step failed). None if git can't say; content then fails."""
    try:
        line, _parents = _first_parent_line(repo, verdict.head, last_good_ledger)
        known = dict(verdict.chain)
        return [[c, known[c] if c in known else commit_signer(repo, c, keyring, trust)] for c in line]
    except _WALK_ERRORS:
        return None


def _cmd_walk(args) -> int:
    """Walk the head from last good. With no state, last good is --anchor itself and the seen list [] (D6). The
    verdict's last good and seen heads are stored, nothing else; a walk that raises writes nothing."""
    state_dir, repo, keyring = Path(args.state), Path(args.repo), Path(args.keyring)
    _unlink(state_dir / WALK_FILE)                       # content never runs on an older walk than this one
    state = load_state(state_dir)
    trust = load_trust(Path(args.trust))
    anchor = _need_sha(args.anchor)
    if state.last_good is None:
        state.last_good, state.seen_heads, state.last_good_ledger = anchor, [], anchor
    elif state.last_good_ledger is None:
        state.last_good_ledger = anchor
    verdict = walk(repo, args.head, state.last_good, keyring, trust, seen_heads=state.seen_heads)
    chain = _ledger_chain(repo, verdict, state.last_good_ledger, keyring, trust) if verdict.valid else None
    if args.mode == "apply":
        apply_commit = verdict.head if verdict.valid else None
    else:
        apply_commit = verdict.newest_trusted
    state.last_good, state.seen_heads = verdict.last_good, list(verdict.seen_heads)
    save_state(state_dir, state)
    out = asdict(verdict)
    out.update(apply_commit=apply_commit, ledger_chain=chain, mode=args.mode, dry=args.dry,
               fallback_statuses=_fallback_statuses(args.mode, verdict))
    _write_json(state_dir / WALK_FILE, out)
    said = "valid" if verdict.valid else f"frozen: {verdict.reason}, {len(verdict.seen_heads)} seen"
    print(f"sso-ledger walk: {args.mode}{' dry' if args.dry else ''} head {verdict.head[:7]} {said}, last good "
          f"{verdict.last_good[:7]}, apply {apply_commit[:7] if apply_commit else 'none'}")
    return 0


def _read_walk(path: Path) -> dict:
    try:
        w = json.loads(path.read_bytes())
    except FileNotFoundError:
        raise UsageError("no walk.json: walk first") from None
    except ValueError:
        raise UsageError("walk.json is not JSON") from None
    names = [f.name for f in fields(WalkVerdict)]
    if type(w) is not dict or not {*names, "apply_commit", "ledger_chain", "mode", "dry"} <= set(w):
        raise UsageError("walk.json is not a walk")
    pairs = ("chain", "invalid", "ledger_chain")
    for key in pairs:
        value = w[key] if w[key] is not None or key != "ledger_chain" else []
        if type(value) is not list or not all(type(p) is list and len(p) == 2 and all(type(x) is str for x in p)
                                              for p in value):
            raise UsageError(f"walk.json: {key} is not a list of pairs")
    if type(w["valid"]) is not bool or type(w["dry"]) is not bool or w["mode"] not in MODES:
        raise UsageError("walk.json: valid, dry or mode is wrong")
    verdict = WalkVerdict(**{**{n: w[n] for n in names}, "chain": [tuple(p) for p in w["chain"]],
                             "invalid": [tuple(p) for p in w["invalid"]]})
    return {"verdict": verdict, "mode": w["mode"], "dry": w["dry"],
            "signers": {c: s for c, s in (w["ledger_chain"] or [])}}


def _effective_ledger(repo: Path, sha: str | None) -> Ledger:
    """The ledger admission reads: ledger.yaml at the effective commit. If even that doesn't parse (an anchor's
    ledger.yaml, say) there is nothing to admit from, and admitted guests keep their stored state."""
    if sha is None:
        return EMPTY_LEDGER
    try:
        return ledger_at(repo, sha)
    except SchemaError:
        return EMPTY_LEDGER


def _cmd_content(args) -> int:
    """The ledger verdict and the guests for this run's walk. state.json is written before the var-file, so a
    guest ever handed to the people layer is always in admitted. --dry decides as check mode does and never
    writes the var-file or admitted."""
    state_dir, repo = Path(args.state), Path(args.repo)
    _unlink(state_dir / CONTENT_FILE)                    # a content step that dies leaves no outputs behind
    if not args.dry:
        _unlink(state_dir / NEXT_FILE)
    state = load_state(state_dir)
    w = _read_walk(Path(args.walk))
    verdict = w["verdict"]
    if w["mode"] != args.mode or w["dry"] != args.dry or verdict.last_good != state.last_good:
        raise UsageError("walk.json is not this run's walk")
    lv = check_ledger(repo, verdict, state.last_good_ledger, signers=w["signers"])
    ledger = _effective_ledger(repo, lv.effective)
    if verdict.valid:
        people = load_people(repo, verdict.head)
        reserved = load_reserved(repo, verdict.head)
        directory = KeycloakDirectory(args.keycloak_url, Path(args.keycloak_secret_file))
        decision = admit(ledger, people, reserved, directory, state, _now(), "check" if args.dry else args.mode)
        state.last_good_ledger = lv.effective
    else:                                                # frozen: nothing new; hand the admitted guests
        decision = Decision([], [], {}, {}, dict(sorted(_hand_admitted(ledger, copy.deepcopy(state.admitted))[0]
                                                         .items())))
    st = statuses(args.mode, verdict, lv, decision)
    save_state(state_dir, state)
    if not args.dry:
        _write_json(state_dir / NEXT_FILE, {"guests": decision.guests})
    _write_json(state_dir / CONTENT_FILE, {
        "mode": args.mode, "ledger": asdict(lv), "admitted": decision.admitted_now,
        "would_admit": decision.would_admit, "refused_entries": decision.refused_now,
        "deferred": decision.deferred, "statuses": st})
    said = ("frozen" if not verdict.valid else f"ledger refused: {lv.reason}" if lv.refused else "ledger ok")
    print(f"sso-ledger content: {args.mode}{' dry' if args.dry else ''} head {verdict.head[:7]} {said}, effective "
          f"{lv.effective[:7] if lv.effective else 'none'}, {len(decision.admitted_now)} admitted, "
          f"{len(decision.would_admit)} would admit, {len(decision.refused_now)} refused, "
          f"{len(decision.deferred)} deferred")
    return 0


def _cmd_settle(args) -> int:
    """After the people apply. --applied: this run's var-file is now what the people layer holds (handed.json).
    --failed-new: the apply with this run's new guests failed and the one with the previous set succeeded, so
    this run's admissions become refusals (apply-failed) and the var-file goes."""
    state_dir = Path(args.state)
    if args.applied:
        nxt = state_dir / NEXT_FILE
        if not nxt.exists():
            raise UsageError("no guests.next.json to promote")
        os.replace(nxt, state_dir / HANDED_FILE)
        _fsync_dir(state_dir)
        print("sso-ledger settle: applied; guests.next.json is now handed.json")
        return 0
    try:
        content = json.loads((state_dir / CONTENT_FILE).read_bytes())
    except FileNotFoundError:
        raise UsageError("no content.json: nothing to settle") from None
    new = content.get("admitted") if type(content) is dict else None
    if type(new) is not list or not all(type(u) is str for u in new):
        raise UsageError("content.json: admitted is not a list")
    state = load_state(state_dir)
    moved = []
    for u in new:
        rec = state.admitted.get(u)
        if rec is None or not rec.get("link"):
            continue
        link = rec["link"]
        del state.admitted[u]
        state.refused[link] = {"reason": "apply-failed", "hash": state.seen.get(link, {}).get("hash")}
        moved.append(link)
    save_state(state_dir, state)
    _unlink(state_dir / NEXT_FILE)
    print(f"sso-ledger settle: failed-new; {len(moved)} refused apply-failed"
          + (f": {','.join(moved)}" if moved else ""))
    return 0


def _cmd_seed(args) -> int:
    """A rebuilt box: fill admitted from `tofu output -json guests` (username to {active, ...}), keeping every
    guest already there. Only `active` is read; no profile reaches the state."""
    state_dir = Path(args.state)
    try:
        data = json.loads(Path(args.source).read_bytes())
    except OSError:
        raise UsageError("cannot read the seed file") from None
    except ValueError:
        raise UsageError("the seed file is not JSON") from None
    if type(data) is not dict or not all(type(u) is str and type(v) is dict and type(v.get("active")) is bool
                                         for u, v in data.items()):
        raise UsageError("the seed file is not `tofu output -json guests`")
    state = load_state(state_dir)
    added = [u for u in data if u not in state.admitted]
    for u in added:
        state.admitted[u] = {"link": None, "at": None, "active": data[u]["active"]}
    save_state(state_dir, state)
    print(f"sso-ledger seed: {len(added)} admitted from the people layer's output, {len(data) - len(added)} kept")
    return 0


def _cmd_forget(args) -> int:
    """An erasure (D9): drop one guest from admitted, under the box's lock."""
    state_dir = Path(args.state)
    state = load_state(state_dir)
    if args.username not in state.admitted:
        raise UsageError(f"{args.username} is not admitted")
    del state.admitted[args.username]
    save_state(state_dir, state)
    print(f"sso-ledger forget: {args.username} removed from admitted")
    return 0


def _cmd_fallback(args) -> int:
    """A content step that failed: the var-file becomes the last handed set, or no guests without one."""
    state_dir = Path(args.state)
    try:
        data = json.loads((state_dir / HANDED_FILE).read_bytes())
    except FileNotFoundError:
        data = {"guests": {}}
    except ValueError:
        raise UsageError("handed.json is not JSON") from None
    if type(data) is not dict or set(data) != {"guests"} or type(data["guests"]) is not dict:
        raise UsageError("handed.json is not a guests var-file")
    _write_json(state_dir / NEXT_FILE, data)
    print(f"sso-ledger fallback: guests.next.json holds the last handed set, {len(data['guests'])} guests")
    return 0


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sso-ledger", description="The box's check of ledger.yaml in sso-people.")
    sub = p.add_subparsers(dest="command", required=True)
    w = sub.add_parser("walk", help="check the commits since last good")
    c = sub.add_parser("content", help="the ledger verdict and the guests")
    for cmd in (w, c):
        cmd.add_argument("--mode", choices=MODES, required=True)
        cmd.add_argument("--repo", required=True)
        cmd.add_argument("--state", required=True)
        cmd.add_argument("--dry", action="store_true", help="ledger-drills: own state, never hands guests")
    for flag in ("--head", "--keyring", "--trust", "--anchor"):
        w.add_argument(flag, required=True)
    for flag in ("--walk", "--keycloak-url", "--keycloak-secret-file"):
        c.add_argument(flag, required=True)
    s = sub.add_parser("settle", help="after the people apply")
    s.add_argument("--state", required=True)
    how = s.add_mutually_exclusive_group(required=True)
    how.add_argument("--applied", action="store_true")
    how.add_argument("--failed-new", action="store_true")
    sd = sub.add_parser("seed", help="fill admitted from tofu output -json guests")
    sd.add_argument("--state", required=True)
    sd.add_argument("--from", dest="source", required=True)
    f = sub.add_parser("forget", help="drop one guest from admitted (an erasure)")
    f.add_argument("--state", required=True)
    f.add_argument("username")
    fb = sub.add_parser("fallback", help="the var-file from the last handed set")
    fb.add_argument("--state", required=True)
    return p


_COMMANDS = {"walk": _cmd_walk, "content": _cmd_content, "settle": _cmd_settle, "seed": _cmd_seed,
             "forget": _cmd_forget, "fallback": _cmd_fallback}
# Exceptions whose text the module writes itself and keeps free of values from files; anything else is named by
# its class alone, so no library's message can carry an email or a name to stderr.
_SAYABLE = (GitError, SchemaError, TransitionError, LookupFailed, UsageError, ValueError)


def main(argv: list[str]) -> int:
    """sso-ledger's command line. Exit 0 on every verdict, a freeze and a refused ledger included; 2 on a usage
    or internal error, a walk that raised included. One summary line on stdout, ids only."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    try:
        return _COMMANDS[args.command](args)
    except Exception as e:
        said = f"{type(e).__name__}: {str(e)[:200]}" if isinstance(e, _SAYABLE) else type(e).__name__
        print(f"sso-ledger {args.command}: failed: {said}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
