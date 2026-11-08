"""The box's commit check: signer classes, the ledger key's path rule, the first-parent walk and recovery
(sso_ledger.commit_signer, check_commit, walk, newest_trusted, parse_reviewed_range, load_trust)."""
import itertools
import json

import pytest

import sso_ledger as L

from .conftest import EMPTY_LEDGER, SEED_PEOPLE

_n = itertools.count(1)


def ledger_bytes() -> bytes:
    """A new ledger.yaml each call. The walk never parses it, so a comment is change enough."""
    return EMPTY_LEDGER + f"# change {next(_n)}\n".encode()


def people_bytes() -> bytes:
    return SEED_PEOPLE + f"# change {next(_n)}\n".encode()


def reviewed(last_good: str, tip: str) -> str:
    return f"Recover the ledger\n\nReviewed-Range: {last_good}..{tip}\n"


@pytest.fixture
def repo(people_repo):
    return people_repo


@pytest.fixture
def walk(repo, keyring, trust):
    return lambda head, last_good: L.walk(repo.path, head, last_good, keyring, trust)


def signer(repo, sha, keyring, trust):
    return L.commit_signer(repo.path, sha, keyring, trust)


# --- trust and signers ----------------------------------------------------------------------------------------

def test_load_trust(tmp_path):
    a, b, c = "a" * 40, "B" * 40, "c" * 40
    path = tmp_path / "people-trust.json"
    path.write_text(json.dumps({"operators": [a], "web_flow": [b], "ledger": [c]}))
    assert L.load_trust(path) == L.Trust(frozenset({"A" * 40}), frozenset({"B" * 40}), frozenset({"C" * 40}))
    for bad in ({"operators": [a], "web_flow": [b]},                                  # a class missing
                {"operators": [a], "web_flow": [b], "ledger": [c], "extra": []},      # an unknown class
                {"operators": [a], "web_flow": [b], "ledger": [a]},                   # one key in two classes
                {"operators": [a.lower()], "web_flow": [b], "ledger": [a.upper()]},
                {"operators": ["a" * 39], "web_flow": [b], "ledger": [c]},            # not a fingerprint
                {"operators": "a" * 40, "web_flow": [b], "ledger": [c]},
                [a, b, c]):
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            L.load_trust(path)


def test_signer_classes(repo, keys, keyring, trust):
    made = {name: repo.commit({"ledger.yaml": ledger_bytes()}, name)
            for name in ("operator", "web-flow", "ledger", "untrusted", None, "expired")}
    got = {name: signer(repo, sha, keyring, trust) for name, sha in made.items()}
    assert got == {"operator": "operator", "web-flow": "web-flow", "ledger": "ledger", "untrusted": "untrusted",
                   None: "untrusted", "expired": "untrusted"}
    # The fixtures mean what they say: the operator signs with a subkey, so the class must come from the
    # primary (%GP); the expired key's signature is good but its key has expired (Y), not merely unknown.
    assert repo.show("%G?|%GF", made["operator"], keyring) != f"G|{keys['operator'].fpr}"
    assert repo.show("%G?|%GP", made["operator"], keyring) == f"G|{keys['operator'].fpr}"
    assert repo.show("%G?", made["expired"], keyring) == "Y"
    assert repo.show("%G?", made["untrusted"], keyring) == "E"


def test_signer_needs_a_class(repo, keys, keyring, trust):
    """A good signature from a key in the keyring but in no class of people-trust.json is untrusted."""
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    only_operators = L.Trust(trust.operators, frozenset(), frozenset())
    assert signer(repo, sha, keyring, only_operators) == "untrusted"


# --- the path rule --------------------------------------------------------------------------------------------

def _case(repo, name: str, who: str) -> str:
    """One commit of the path-rule table, signed by `who`, built on the seed."""
    base = repo.seed
    gitlink = b"0123456789abcdef0123456789abcdef01234567"
    if name == "ledger only":
        return repo.commit({"ledger.yaml": ledger_bytes()}, who, parents=[base])
    if name == "also people.yaml":
        return repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, who, parents=[base])
    if name == "people.yaml only":
        return repo.commit({"people.yaml": people_bytes()}, who, parents=[base])
    if name == "a ledger.yaml elsewhere":
        return repo.commit({"sub/ledger.yaml": ledger_bytes()}, who, parents=[base])
    if name == "rename":
        return repo.commit({"ledger.yaml": None, "ledger-old.yaml": EMPTY_LEDGER}, who, parents=[base])
    if name == "submodule beside":
        return repo.commit({"ledger.yaml": ledger_bytes(), "vendor": gitlink}, who, parents=[base],
                           mode={"vendor": "160000"})
    if name == "mode 100755":
        return repo.commit({"ledger.yaml": EMPTY_LEDGER}, who, parents=[base], mode="100755")
    if name == "symlink":
        return repo.commit({"ledger.yaml": b"people.yaml"}, who, parents=[base], mode="120000")
    if name == "submodule in place":
        return repo.commit({"ledger.yaml": gitlink}, who, parents=[base], mode="160000")
    if name == "creates":
        gone = repo.commit({"ledger.yaml": None}, "operator", parents=[base])
        return repo.commit({"ledger.yaml": EMPTY_LEDGER}, who, parents=[gone])
    if name == "deletes":
        return repo.commit({"ledger.yaml": None}, who, parents=[base])
    if name == "changes nothing":
        return repo.commit({}, who, parents=[base])
    if name == "two parents":
        side = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base])
        return repo.commit({"ledger.yaml": ledger_bytes()}, who, parents=[base, side])
    if name == "no parent":
        return repo.commit({"ledger.yaml": EMPTY_LEDGER, "people.yaml": SEED_PEOPLE}, who, parents=[])
    raise AssertionError(name)


PATH_RULE = {
    "ledger only": None,
    "also people.yaml": "ledger-path",
    "people.yaml only": "ledger-path",
    "a ledger.yaml elsewhere": "ledger-path",
    "rename": "ledger-path",
    "submodule beside": "ledger-path",
    "mode 100755": "ledger-mode",
    "symlink": "ledger-mode",
    "submodule in place": "ledger-mode",
    "creates": "ledger-status",
    "deletes": "ledger-status",
    "changes nothing": "ledger-status",
    "two parents": "ledger-merge",
    "no parent": "ledger-merge",
}


@pytest.mark.parametrize("name", list(PATH_RULE))
def test_ledger_key_path_rule(name, repo, keyring, trust):
    sha = _case(repo, name, "ledger")
    assert signer(repo, sha, keyring, trust) == "ledger"
    assert L.check_commit(repo.path, sha, "ledger") == PATH_RULE[name]


@pytest.mark.parametrize("who", ["operator", "web-flow"])
@pytest.mark.parametrize("name", list(PATH_RULE))
def test_operator_and_web_flow_may_change_any_path(name, who, repo, keyring, trust):
    sha = _case(repo, name, who)
    cls = signer(repo, sha, keyring, trust)
    assert cls == who
    assert L.check_commit(repo.path, sha, cls) is None


@pytest.mark.parametrize("who,code", [(None, "unsigned"), ("untrusted", "untrusted-signer"),
                                      ("expired", "untrusted-signer")])
def test_unsigned_or_unknown_key_invalid(who, code, repo, keyring, trust):
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, who)
    assert L.check_commit(repo.path, sha, signer(repo, sha, keyring, trust)) == code


# --- the walk -------------------------------------------------------------------------------------------------

def test_merge_counts_against_first_parent(repo, walk):
    base = repo.seed
    inner1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    inner2 = repo.commit({"ledger.yaml": ledger_bytes(), "notes.md": b"x\n"}, "untrusted")
    merge = repo.commit({"people.yaml": people_bytes(), "notes.md": b"x\n"}, "web-flow", parents=[base, inner2])
    v = walk(merge, base)
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert v.chain == [(merge, "web-flow")]
    assert inner1 not in dict(v.chain) and inner2 not in dict(v.chain)


def test_valid_chain(repo, walk):
    base = repo.seed
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    l1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    wf = repo.commit({"people.yaml": people_bytes(), "ledger.yaml": ledger_bytes()}, "web-flow")
    l2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(l2, base)
    assert v == L.WalkVerdict(head=l2, last_good=l2, valid=True, reason=None,
                              chain=[(op, "operator"), (l1, "ledger"), (wf, "web-flow"), (l2, "ledger")],
                              invalid=[], recovery=None, newest_trusted=wf)


def test_head_is_last_good(repo, walk):
    v = walk(repo.seed, repo.seed)
    assert (v.valid, v.chain, v.last_good, v.newest_trusted) == (True, [], repo.seed, repo.seed)


def test_freeze_on_invalid_commit(repo, walk):
    base = repo.seed
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    wf = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(head, base)
    assert v.valid is False
    assert v.reason == f"invalid:ledger-path@{bad[:7]}"
    assert v.invalid == [(bad, "ledger-path")]
    assert (v.last_good, v.recovery, v.newest_trusted) == (base, None, wf)
    assert len(v.chain) == 5


def test_freeze_lists_every_invalid_commit(repo, walk):
    base = repo.seed
    unsigned = repo.commit({"people.yaml": people_bytes()}, None)
    stranger = repo.commit({"ledger.yaml": ledger_bytes()}, "untrusted")
    merge = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[stranger, base])
    v = walk(merge, base)
    assert v.reason == f"invalid:unsigned@{unsigned[:7]}"
    assert v.invalid == [(unsigned, "unsigned"), (stranger, "untrusted-signer"), (merge, "ledger-merge")]
    assert v.newest_trusted == base


def test_freeze_on_non_fast_forward(repo, walk):
    a = repo.commit({"people.yaml": people_bytes()}, "operator")
    b = repo.commit({"people.yaml": people_bytes()}, "operator")
    c = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[a])
    v = walk(c, b)
    assert (v.valid, v.reason, v.invalid, v.last_good) == (False, "not-fast-forward", [], b)
    assert v.chain == [(c, "operator")]
    assert v.newest_trusted == c


# --- recovery -------------------------------------------------------------------------------------------------

def _frozen(repo):
    """last good, a ledger-key commit that also changed people.yaml, and an operator's revert of it."""
    last_good = repo.seed
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    return last_good, bad, revert


def test_recovery_accepted(repo, walk):
    last_good, bad, revert = _frozen(repo)
    assert walk(revert, last_good).reason == f"invalid:ledger-path@{bad[:7]}"
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery, v.last_good, v.invalid) == (True, None, rec, rec, [])
    assert [c for c, _ in v.chain] == [bad, revert, rec]


def test_recovery_with_the_revert_as_tip(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, revert))
    assert (walk(rec, last_good).valid, walk(rec, last_good).recovery) == (True, rec)


def test_recovery_replayed_fails(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    assert walk(rec, last_good).valid
    # Last good moves past it onto history `rec` is not part of (an erasure rewrite the box took) ...
    rewritten = repo.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, None, parents=[])
    erasure = repo.commit({}, "operator", message=reviewed(rec, rewritten))
    assert walk(erasure, rec).valid
    # ... and the old recovery commit comes back as the head, or under a new one.
    v = walk(rec, erasure)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-stale-last-good@{rec[:7]}", None)
    on_top = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[rec])
    assert walk(on_top, erasure).reason == f"recovery-stale-last-good@{rec[:7]}"


@pytest.mark.parametrize("who", ["web-flow", "ledger"])
def test_recovery_must_be_operator_key(who, repo, walk):
    last_good, bad, revert = _frozen(repo)
    change = {"ledger.yaml": ledger_bytes()} if who == "ledger" else {}
    rec = repo.commit(change, who, message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-not-operator-key@{rec[:7]}", None)
    assert v.invalid == [(bad, "ledger-path")]


@pytest.mark.parametrize("form", ["both short", "tip short", "last good short", "two trailers", "no range",
                                  "three dots"])
def test_recovery_needs_full_shas(form, repo, walk):
    last_good, bad, revert = _frozen(repo)
    message = {
        "both short": f"Recover\n\nReviewed-Range: {last_good[:7]}..{bad[:7]}\n",
        "tip short": f"Recover\n\nReviewed-Range: {last_good}..{bad[:7]}\n",
        "last good short": f"Recover\n\nReviewed-Range: {last_good[:12]}..{bad}\n",
        "two trailers": f"Recover\n\nReviewed-Range: {last_good}..{bad}\nReviewed-Range: {last_good}..{revert}\n",
        "no range": f"Recover\n\nReviewed-Range: {bad}\n",
        "three dots": f"Recover\n\nReviewed-Range: {last_good}...{bad}\n",
    }[form]
    rec = repo.commit({}, "operator", message=message)
    v = walk(rec, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-bad-trailer@{rec[:7]}")


def test_parse_reviewed_range():
    a, b = "a" * 40, "b" * 40
    assert L.parse_reviewed_range(f"{a}..{b}\n") == (a, b)
    assert L.parse_reviewed_range(f"{a.upper()}..{b}\n") == (a, b)
    for bad in ("", "\n", f"{a[:7]}..{b[:7]}\n", f"{a}..{b}\n{a}..{b}\n", f"{a}...{b}\n", f"{a}..{b} x\n",
                f"{a}..\n", f"{a}{b}\n", f"{a}..{b}0\n", "g" * 40 + f"..{b}\n"):
        assert L.parse_reviewed_range(bad) is None, bad


@pytest.mark.parametrize("tip", ["a side branch", "a missing commit"])
def test_recovery_tip_must_be_ancestor(tip, repo, walk):
    last_good, bad, revert = _frozen(repo)
    side = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[bad])
    named = side if tip == "a side branch" else "f" * 40
    rec = repo.commit({}, "operator", parents=[revert], message=reviewed(last_good, named))
    v = walk(rec, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-tip-not-ancestor@{rec[:7]}")


def test_recovery_must_cover_every_invalid_commit(repo, walk):
    last_good, bad, revert = _frozen(repo)
    missed = repo.commit({"ledger.yaml": ledger_bytes()}, None)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-misses@{missed[:7]}", None)
    assert v.invalid == [(missed, "unsigned")]


def test_commits_after_recovery_checked_as_usual(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    fine = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert (walk(fine, last_good).valid, walk(fine, last_good).recovery) == (True, rec)
    after = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    v = walk(after, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:ledger-path@{after[:7]}", None)
    assert v.invalid == [(after, "ledger-path")]
    # The operator's remedy: revert again and review the whole range from the same last good.
    again = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    rec2 = repo.commit({}, "operator", message=reviewed(last_good, after))
    assert (walk(rec2, last_good).valid, walk(rec2, last_good).recovery) == (True, rec2)
    assert again in dict(walk(rec2, last_good).chain)


def test_newest_recovery_attempt_is_the_one_judged(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    # A later web-flow commit quoting the trailer neither breaks the accepted recovery nor stands in for one.
    quoted = repo.commit({}, "web-flow", message=reviewed(last_good, bad))
    v = walk(quoted, last_good)
    assert (v.valid, v.recovery) == (True, rec)


def test_recovery_takes_non_fast_forward_history(repo, walk):
    """The erasure shape: filter-repo rewrites history (its commits come out unsigned) and an operator signs
    a head naming the box's last good and the rewritten tip, then force-pushes."""
    old = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    old_tip = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    r1 = repo.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, None, parents=[])
    r2 = repo.commit({"ledger.yaml": ledger_bytes()}, None)
    r3 = repo.commit({"people.yaml": people_bytes()}, None)
    assert walk(r3, old_tip).reason == "not-fast-forward"
    rec = repo.commit({}, "operator", message=reviewed(old_tip, r3))
    v = walk(rec, old_tip)
    assert (v.valid, v.reason, v.recovery, v.last_good, v.invalid) == (True, None, rec, rec, [])
    assert [c for c, _ in v.chain] == [r1, r2, r3, rec]
    assert old not in dict(v.chain)
    # Without the trailer the same rewrite stays frozen.
    plain = repo.commit({}, "operator", parents=[r3])
    assert walk(plain, old_tip).reason == "not-fast-forward"


# --- newest trusted, inputs, and how git is called --------------------------------------------------------------

def test_newest_trusted(repo, keyring, trust):
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    repo.commit({"ledger.yaml": ledger_bytes()}, None)
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "expired")
    assert L.newest_trusted(repo.path, head, keyring, trust) == op
    # Second parents don't count: only the first-parent line is searched.
    side = repo.commit({"people.yaml": people_bytes()}, "web-flow", parents=[repo.seed])
    merge = repo.commit({}, None, parents=[head, side])
    assert L.newest_trusted(repo.path, merge, keyring, trust) == op
    lone = repo.commit({"ledger.yaml": EMPTY_LEDGER}, "ledger", parents=[])
    assert L.newest_trusted(repo.path, lone, keyring, trust) is None


def test_walk_refuses_bad_input(repo, walk):
    for bad in (repo.seed[:7], "--all", "HEAD", "g" * 40, repo.seed.upper()):
        with pytest.raises(ValueError):
            walk(bad, repo.seed)
        with pytest.raises(ValueError):
            walk(repo.seed, bad)
    with pytest.raises(L.GitError):
        walk(repo.seed, "e" * 40)                # a last good that isn't in the checkout


def test_walk_reads_git_only(repo, walk, monkeypatch):
    """walk never parses YAML (D2), and every git call has a 30 s timeout and the C locale."""
    base = repo.seed
    repo.commit({"ledger.yaml": b"version: [\n"}, "ledger")
    bad = repo.commit({"ledger.yaml": b"&a x: *a\n", "people.yaml": people_bytes()}, "ledger")
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    head = repo.commit({}, "operator", message=reviewed(base, bad))
    calls = []
    real_run = L.subprocess.run

    def run(cmd, *args, **kw):
        calls.append((cmd, kw.get("timeout"), (kw.get("env") or {}).get("LC_ALL")))
        return real_run(cmd, *args, **kw)

    def no_yaml(*_args, **_kw):
        raise AssertionError("walk parsed YAML")

    monkeypatch.setattr(L.subprocess, "run", run)
    monkeypatch.setattr(L, "parse_ledger", no_yaml)
    monkeypatch.setattr(L.yaml, "load", no_yaml)
    monkeypatch.setattr(L.yaml, "safe_load", no_yaml)
    monkeypatch.setattr(L._Loader, "get_single_data", no_yaml)
    v = walk(head, base)
    assert (v.valid, v.recovery) == (True, head)
    assert revert in dict(v.chain)
    assert calls
    assert {c[0][0] for c in calls} == {"git"}
    assert {(c[1], c[2]) for c in calls} == {(30, "C")}
