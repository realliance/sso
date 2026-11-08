#!/opt/ansible/bin/python3 -I
"""sso-ledger: the box's check of ledger.yaml in realliance/sso-people.

Managed by realliance/sso (host/roles/config_apply), installed as /usr/local/sbin/sso-ledger. It runs in the
pull role's Python 3.12 venv, whose PyYAML ansible-core already needs, and stays 3.12 compatible.

The invite service writes ledger.yaml with its own key. This code is what keeps that key harmless: a commit
signed with it may change ledger.yaml alone, and the file it writes must parse strictly and change only in
the ways the ledger key may change it. Errors name codes, keys, link ids and lines, never a value from the
file, because a value may be an email or a name.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

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
Signer = Literal["operator", "web-flow", "ledger", "untrusted"]

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
    """people-trust.json: the primary-key fingerprints of each signer class."""
    operators: frozenset[str]
    web_flow: frozenset[str]
    ledger: frozenset[str]


def load_trust(path: Path) -> Trust:
    """Read people-trust.json, {"operators": [...], "web_flow": [...], "ledger": [...]}, or raise ValueError."""
    data = json.loads(Path(path).read_text())
    names = ("operators", "web_flow", "ledger")
    if type(data) is not dict or set(data) != set(names):
        raise ValueError(f"{path}: needs exactly the keys {', '.join(names)}")
    classes = {}
    for name in names:
        fprs = data[name]
        if type(fprs) is not list or not all(type(f) is str and _FPR.fullmatch(f) for f in fprs):
            raise ValueError(f"{path}: {name} must be a list of 40-hex fingerprints")
        classes[name] = frozenset(f.upper() for f in fprs)
    for a, b in ((0, 1), (0, 2), (1, 2)):
        if classes[names[a]] & classes[names[b]]:
            raise ValueError(f"{path}: a fingerprint is in both {names[a]} and {names[b]}")
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
    its primary. Unsigned, unknown, expired, revoked or untrusted keys are all "untrusted"."""
    out = _git(repo, "log", "-1", "--no-show-signature", "--format=%G?%x00%GP", _need_sha(sha),
               gnupghome=keyring).stdout.decode(errors="replace")
    status, sep, fpr = out.rstrip("\n").partition("\0")
    if not sep or status != "G":
        return "untrusted"
    fpr = fpr.strip().upper()
    if fpr in trust.operators:
        return "operator"
    if fpr in trust.web_flow:
        return "web-flow"
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

    An operator key or web-flow may change any path. The ledger key may change ledger.yaml alone, in a commit
    with one parent, as one `:100644 100644 <a> <b> M ledger.yaml` line of `git diff-tree --raw --no-renames
    -r <parent> <sha>`. Anyone else makes the commit invalid."""
    sha = _need_sha(sha)
    if signer in ("operator", "web-flow"):
        return None
    parents, signed = _commit_object(repo, sha)
    if signer == "untrusted":
        return "untrusted-signer" if signed else "unsigned"
    if signer != "ledger":
        raise ValueError(f"unknown signer class {signer}")
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


@dataclass(frozen=True)
class WalkVerdict:
    head: str
    last_good: str                       # the last good commit after this walk: the head when valid
    valid: bool
    reason: str | None                   # why not valid; None when valid
    chain: list[tuple[str, str]]         # (commit, signer class), oldest first
    invalid: list[tuple[str, str]]       # (commit, code) of the commits that freeze, oldest first
    recovery: str | None                 # the Reviewed-Range commit the box took, if any
    newest_trusted: str | None           # the newest first-parent commit an operator key or web-flow signed
    last_seen: str | None = None         # what the caller stores as last seen: see walk()


_TRUSTED: tuple[str, ...] = ("operator", "web-flow")


def newest_trusted(repo: Path, head: str, keyring: Path, trust: Trust, *,
                   _known: dict[str, str] | None = None) -> str | None:
    """The newest commit on head's first-parent line that an operator key or web-flow signed."""
    known = _known or {}
    for sha in _rev_list(repo, "--first-parent", _need_sha(head)):
        cls = known.get(sha) or commit_signer(repo, sha, keyring, trust)
        if cls in _TRUSTED:
            return sha
    return None


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


def walk(repo: Path, head: str, last_good: str, keyring: Path, trust: Trust,
         last_seen: str | None = None) -> WalkVerdict:
    """Check `last_good..head` (D5, with the rulings of fix rounds 1-3).

    - Every first-parent commit from last good (exclusive) to head is checked by its signer.
    - A merge counts as one change against its first parent only when web-flow signed it: GitHub always keeps
      main's tip as the first parent, so what it brings in on other parents is PR work that needs no signature
      of its own. Under any other merge, an operator's local `git pull` included, every commit brought in is
      checked like a first-parent one, so a push that froze the box can't come back in on a second parent.
    - A ledger-key commit is held to the path rule wherever it is.
    - `last_seen`, the previous head the box saw (valid or not), must sit on head's first-parent line, or the
      walk freezes with `not-first-parent-descendant@<last_seen>`. Every way GitHub lands a change on main
      keeps the old tip there; a web-flow merge that made it a second parent ("Update branch" on a PR, then
      a fast-forward of main) does not, and would otherwise carry it in unchecked. None (a first run or a
      rebuilt box) skips the check. The verdict's `last_seen` is what the caller stores: head when the check
      passed or a recovery took the history, else the old value, so the freeze holds through later pushes.

    The chain is valid when head fast-forwards from last good and keeps last seen on its first-parent line,
    or when a Reviewed-Range recovery commit accepts the history, and every checked commit outside the reviewed
    range is valid. A recovery commit is the newest chain commit an operator key signed whose trailer is
    `<L>..<T>`; the box takes it only if L is its last good and T is an ancestor of it, and then reviews T's
    history less last good's. If last seen left the first-parent line but is still in the recovery's history,
    the reviewed range must hold it too.

    Ranges come from ancestry, never from `git rev-list A ^B`: that stops walking B's history a few commits
    after only excluded ones are left (git's SLOP), so commit dates, which signers choose, could pull
    already-checked history back into the range."""
    _need_commit(repo, head)
    _need_commit(repo, last_good)
    if last_seen is not None:
        _need_sha(last_seen)
    if _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() != b"false":
        # A shallow checkout cuts parents off, so the walk can't see the whole range: refuse it.
        return WalkVerdict(head=head, last_good=last_good, valid=False, reason="shallow-repository", chain=[],
                           invalid=[], recovery=None, newest_trusted=newest_trusted(repo, head, keyring, trust),
                           last_seen=last_seen)
    tips = [head, last_good] + ([last_seen] if last_seen is not None and _exists(repo, last_seen) else [])
    graph_order, parents = _graph(repo, *tips)
    done = _ancestors(parents, last_good)
    under_head = _ancestors(parents, head)
    fast_forward = last_good in under_head
    order, c = [], head                                  # the first-parent chain, oldest first
    while c not in done:
        order.append(c)
        if not parents[c]:
            break
        c = parents[c][0]
    order.reverse()
    line, c = set(), head                                # head's whole first-parent line
    while c in parents and c not in line:
        line.add(c)
        c = parents[c][0] if parents[c] else None
    on_line = last_seen is None or last_seen in line
    # Which chain commit brings each other commit in: the oldest one whose history holds it.
    brought_in_by, seen = {}, set(done)
    for m in order:
        seen.add(m)
        stack = list(parents[m][1:])
        while stack:
            c = stack.pop()
            if c not in seen and c in parents:
                seen.add(c)
                brought_in_by[c] = m
                stack.extend(parents[c])
    signers = {c: commit_signer(repo, c, keyring, trust) for c in order}
    codes = {c: check_commit(repo, c, signers[c]) for c in order}
    chain = [(c, signers[c]) for c in order]
    everything = [c for c in graph_order if c in under_head and c not in done]   # parents before children
    for c in everything:
        if c in codes:
            continue
        cls = commit_signer(repo, c, keyring, trust)
        if cls == "ledger" or signers.get(brought_in_by.get(c)) != "web-flow":
            codes[c] = check_commit(repo, c, cls)
    trusted = newest_trusted(repo, head, keyring, trust, _known=signers)

    # Newest first: the recovery candidate is the newest operator-signed commit with a well-formed trailer.
    # Only operator and web-flow commits make recovery attempts; a trailer on any other commit is ignored, so a
    # ledger-key commit can never mask the freeze's reason. If the chain stays frozen, the reason names what
    # was wrong with the newest attempt.
    attempt_problem, candidate = None, None
    for c in reversed(order):
        if signers[c] not in _TRUSTED:
            continue
        text = _trailer(repo, c)
        if not text.strip():
            continue
        parsed = parse_reviewed_range(text)
        if signers[c] == "operator" and parsed is not None:
            candidate = (c, *parsed)
            break
        attempt_problem = attempt_problem or (f"recovery-not-operator-key@{c[:7]}" if signers[c] != "operator"
                                              else f"recovery-bad-trailer@{c[:7]}")

    recovery, reviewed, under_recovery = None, set(), set()
    if candidate is not None:
        rec, named_last_good, tip = candidate
        under_recovery = _ancestors(parents, rec)
        if named_last_good != last_good:
            attempt_problem = attempt_problem or f"recovery-stale-last-good@{rec[:7]}"
        elif tip == rec or tip not in under_recovery:
            attempt_problem = attempt_problem or f"recovery-tip-not-ancestor@{rec[:7]}"
        else:
            recovery = rec
            reviewed = _ancestors(parents, tip) - done

    invalid = [(c, codes[c]) for c in everything if codes.get(c) is not None and c not in reviewed]
    if recovery is not None:
        missed_seen = (not on_line and last_seen in under_recovery and last_seen not in done
                       and last_seen not in reviewed)
        valid = not invalid and not missed_seen
        reason = None
        if invalid:                      # in the recovery's own history it should have been reviewed
            c, code = invalid[0]
            reason = f"recovery-misses@{c[:7]}" if c in under_recovery else f"invalid:{code}@{c[:7]}"
        elif missed_seen:
            reason = f"recovery-misses@{last_seen[:7]}"
    else:
        valid = fast_forward and on_line and not invalid
        reason = None
        if not valid:                    # an operator's failed attempt, else the first invalid commit
            if attempt_problem:
                reason = attempt_problem
            elif invalid:
                c, code = invalid[0]
                reason = f"invalid:{code}@{c[:7]}"
            elif not on_line:
                reason = f"not-first-parent-descendant@{last_seen[:7]}"
            else:
                reason = "not-fast-forward"
    seen_next = head if on_line or (recovery is not None and valid) else last_seen
    return WalkVerdict(head=head, last_good=head if valid else last_good, valid=valid, reason=reason,
                       chain=chain, invalid=invalid, recovery=recovery if valid else None,
                       newest_trusted=trusted, last_seen=seen_next)
